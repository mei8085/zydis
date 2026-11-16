/***************************************************************************************************

  Zydis relocation integration test

  Verifies that relative branches (JMP/CALL/Jcc/LOOP/J(C/E/R)CXZ) and RIP/EIP-relative memory
  operands survive relocation:

    decode(old_addr) -> ZydisCalcAbsoluteAddress -> encoder request with absolute target ->
    ZydisEncoderEncodeInstructionAbsolute(new_addr) -> decode(new_addr) ->
    ZydisCalcAbsoluteAddress == original target

  The pass criterion is equality of the final absolute target address AND of the remaining
  operand semantics (mnemonic, operand types, registers, non-relative immediates, memory
  segment/base/index/scale/size) -- never merely "re-decoding succeeded".

  Inputs that cannot be re-encoded equivalently at the new address (displacement does not fit
  the instruction's branch/displacement width) must fail with an explicit error status. Silent
  truncation of the displacement or emission of an instruction that jumps elsewhere is a test
  failure.

  Coverage: 16/32/64-bit modes, rel8/rel16/rel32 displacement boundaries (+-2^(n-1) edge
  values), RIP-relative disp32 boundaries, and re-encoding with a forced wider branch width
  (instruction length changes between decode and re-encode).

***************************************************************************************************/

#include <Zydis/Zydis.h>

#include <inttypes.h>
#include <stdio.h>
#include <string.h>

/* ============================================================================================== */
/* Test framework                                                                                 */
/* ============================================================================================== */

static int g_pass_count = 0;
static int g_fail_count = 0;

#define CHECK(cond, ...)                                                        \
    do                                                                          \
    {                                                                           \
        if (!(cond))                                                            \
        {                                                                       \
            printf("    FAIL: %s:%d: ", __FILE__, __LINE__);                    \
            printf(__VA_ARGS__);                                                \
            printf("\n");                                                       \
            return ZYAN_FALSE;                                                  \
        }                                                                       \
    } while (0)

typedef enum Expect_
{
    EXPECT_OK,   // relocation must succeed and preserve the absolute target
    EXPECT_FAIL, // relocation must fail explicitly (no silent truncation)
} Expect;

typedef struct TestCase_
{
    const char *name;
    ZydisMachineMode machine_mode;
    ZydisStackWidth stack_width;
    ZyanU8 bytes[ZYDIS_MAX_INSTRUCTION_LENGTH];
    ZyanU8 length;
    ZyanU64 old_addr;
    ZyanU64 new_addr;
    Expect expect;
    ZydisBranchWidth force_width; // ZYDIS_BRANCH_WIDTH_NONE = keep decoded width
    ZyanU8 expect_len;            // 0 = don't care; else expected re-encoded length
} TestCase;

/* ============================================================================================== */
/* Helpers                                                                                        */
/* ============================================================================================== */

/**
 * Returns the index of the visible operand that carries a relocatable address (relative
 * immediate, RIP/EIP-relative memory operand or absolute moffs memory operand), or -1.
 */
static int FindRelocatableOperand(const ZydisDecodedOperand *operands, ZyanU8 count)
{
    for (ZyanU8 i = 0; i < count; ++i)
    {
        const ZydisDecodedOperand *op = &operands[i];
        if (op->type == ZYDIS_OPERAND_TYPE_IMMEDIATE && op->imm.is_relative)
        {
            return (int)i;
        }
        if (op->type == ZYDIS_OPERAND_TYPE_MEMORY && op->mem.disp.size &&
            ((op->mem.base == ZYDIS_REGISTER_RIP) || (op->mem.base == ZYDIS_REGISTER_EIP) ||
             ((op->mem.base == ZYDIS_REGISTER_NONE) &&
              (op->mem.index == ZYDIS_REGISTER_NONE))))
        {
            return (int)i;
        }
    }
    return -1;
}

/**
 * Compares the operand semantics of two decodings of "the same" instruction before/after
 * relocation. The relocatable operand's displacement/immediate value itself is exempt (it is
 * supposed to change); its absolute target is verified separately.
 */
static ZyanBool CompareSemantics(const ZydisDecodedInstruction *insn_a,
    const ZydisDecodedOperand *ops_a, const ZydisDecodedInstruction *insn_b,
    const ZydisDecodedOperand *ops_b, int reloc_op_index)
{
    CHECK(insn_a->mnemonic == insn_b->mnemonic, "mnemonic changed (%s -> %s)",
        ZydisMnemonicGetString(insn_a->mnemonic), ZydisMnemonicGetString(insn_b->mnemonic));
    CHECK(insn_a->machine_mode == insn_b->machine_mode, "machine mode changed");
    CHECK(insn_a->operand_count_visible == insn_b->operand_count_visible,
        "visible operand count changed (%u -> %u)", insn_a->operand_count_visible,
        insn_b->operand_count_visible);

    for (ZyanU8 i = 0; i < insn_a->operand_count_visible; ++i)
    {
        const ZydisDecodedOperand *a = &ops_a[i];
        const ZydisDecodedOperand *b = &ops_b[i];
        CHECK(a->type == b->type, "operand %u: type changed (%d -> %d)", i, a->type, b->type);
        switch (a->type)
        {
        case ZYDIS_OPERAND_TYPE_REGISTER:
            CHECK(a->reg.value == b->reg.value, "operand %u: register changed", i);
            break;
        case ZYDIS_OPERAND_TYPE_MEMORY:
            CHECK(a->mem.segment == b->mem.segment, "operand %u: mem segment changed", i);
            CHECK(a->mem.base == b->mem.base, "operand %u: mem base changed", i);
            CHECK(a->mem.index == b->mem.index, "operand %u: mem index changed", i);
            CHECK(a->mem.scale == b->mem.scale, "operand %u: mem scale changed", i);
            CHECK(a->size == b->size, "operand %u: operand size changed", i);
            if ((int)i != reloc_op_index)
            {
                CHECK(a->mem.disp.value == b->mem.disp.value,
                    "operand %u: unexpected displacement change", i);
            }
            break;
        case ZYDIS_OPERAND_TYPE_IMMEDIATE:
            if ((int)i != reloc_op_index)
            {
                CHECK(a->imm.value.u == b->imm.value.u,
                    "operand %u: unexpected immediate change", i);
            }
            break;
        default:
            break;
        }
    }
    return ZYAN_TRUE;
}

/**
 * Decodes, computes the absolute target, re-encodes at the new address, re-decodes and
 * verifies that the absolute target and all other operand semantics are preserved.
 */
static ZyanBool RunRelocation(const TestCase *tc)
{
    ZydisDecoder decoder;
    ZyanStatus status = ZydisDecoderInit(&decoder, tc->machine_mode, tc->stack_width);
    CHECK(ZYAN_SUCCESS(status), "decoder init failed: 0x%08X", status);

    // 1. Decode the original instruction at its original runtime address.
    ZydisDecodedInstruction insn;
    ZydisDecodedOperand ops[ZYDIS_MAX_OPERAND_COUNT];
    status = ZydisDecoderDecodeFull(&decoder, tc->bytes, tc->length, &insn, ops);
    CHECK(ZYAN_SUCCESS(status), "initial decode failed: 0x%08X", status);
    CHECK(insn.length == tc->length, "decode consumed %u of %u bytes", insn.length, tc->length);

    const int reloc_op = FindRelocatableOperand(ops, insn.operand_count_visible);
    CHECK(reloc_op >= 0, "no relocatable operand found");

    // 2. Compute the absolute target address at the original location.
    ZyanU64 target = 0;
    status = ZydisCalcAbsoluteAddress(&insn, &ops[reloc_op], tc->old_addr, &target);
    CHECK(ZYAN_SUCCESS(status), "ZydisCalcAbsoluteAddress failed: 0x%08X", status);

    // 3. Convert to an encoder request and plug in the absolute target.
    ZydisEncoderRequest req;
    status = ZydisEncoderDecodedInstructionToEncoderRequest(&insn, ops,
        insn.operand_count_visible, &req);
    CHECK(ZYAN_SUCCESS(status), "DecodedInstructionToEncoderRequest failed: 0x%08X", status);

    ZydisEncoderOperand *req_op = &req.operands[reloc_op];
    if (req_op->type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
    {
        req_op->imm.u = target;
    }
    else
    {
        req_op->mem.displacement = (ZyanI64)target;
    }

    if (tc->force_width != ZYDIS_BRANCH_WIDTH_NONE)
    {
        // Force a different physical branch width (changes the instruction length) and let
        // the encoder pick the matching branch type for it.
        req.branch_width = tc->force_width;
        req.branch_type = ZYDIS_BRANCH_TYPE_NONE;
    }

    // 4. Re-encode at the new runtime address.
    ZyanU8 enc_buf[ZYDIS_MAX_INSTRUCTION_LENGTH];
    ZyanUSize enc_len = sizeof(enc_buf);
    status = ZydisEncoderEncodeInstructionAbsolute(&req, enc_buf, &enc_len, tc->new_addr);

    if (tc->expect == EXPECT_FAIL)
    {
        // Must fail explicitly. A "successful" encode here would mean the displacement was
        // silently truncated and the instruction would jump to a different address.
        CHECK(ZYAN_FAILED(status),
            "expected explicit failure but encoding succeeded (%u bytes)", (ZyanU32)enc_len);
        printf("    explicit error as required: 0x%08X\n", status);
        return ZYAN_TRUE;
    }

    CHECK(ZYAN_SUCCESS(status), "encoding failed unexpectedly: 0x%08X", status);
    if (tc->expect_len)
    {
        CHECK(enc_len == tc->expect_len, "expected re-encoded length %u, got %u",
            (ZyanU32)tc->expect_len, (ZyanU32)enc_len);
    }

    // 5. Re-decode at the new location and compute the absolute target again.
    ZydisDecodedInstruction insn2;
    ZydisDecodedOperand ops2[ZYDIS_MAX_OPERAND_COUNT];
    status = ZydisDecoderDecodeFull(&decoder, enc_buf, enc_len, &insn2, ops2);
    CHECK(ZYAN_SUCCESS(status), "re-decode failed: 0x%08X", status);
    CHECK(insn2.length == enc_len, "re-decode length mismatch");

    CHECK(reloc_op < insn2.operand_count_visible, "relocatable operand vanished");
    ZyanU64 target2 = 0;
    status = ZydisCalcAbsoluteAddress(&insn2, &ops2[reloc_op], tc->new_addr, &target2);
    CHECK(ZYAN_SUCCESS(status), "ZydisCalcAbsoluteAddress (re-decoded) failed: 0x%08X", status);

    // 6. The final target address must be identical -- this is the actual pass criterion.
    CHECK(target2 == target,
        "target mismatch after relocation: 0x%016" PRIX64 " -> 0x%016" PRIX64, target, target2);

    // 7. All other operand semantics must be identical as well.
    CHECK(CompareSemantics(&insn, ops, &insn2, ops2, reloc_op), "semantics changed");

    printf("    target 0x%016" PRIX64 " preserved (%u -> %u bytes)\n", target, insn.length,
        (ZyanU32)enc_len);
    return ZYAN_TRUE;
}

static void RunCase(const TestCase *tc)
{
    printf("[%-56s] ", tc->name);
    if (RunRelocation(tc))
    {
        printf("  PASS\n");
        ++g_pass_count;
    }
    else
    {
        printf("  FAIL\n");
        ++g_fail_count;
    }
}

/* ============================================================================================== */
/* Chained relocation (decode -> abs -> re-encode, repeatedly)                                    */
/* ============================================================================================== */

/**
 * Relocates one instruction through a chain of addresses, verifying after every hop that the
 * absolute target is still the original one. The final hop returns to the original address
 * and must reproduce the original bytes.
 */
static ZyanBool RunChain(const char *name, ZydisMachineMode mode, ZydisStackWidth stack,
    const ZyanU8 *bytes, ZyanU8 length, const ZyanU64 *addrs, ZyanU8 addr_count,
    ZydisBranchWidth width_at_hop_1, ZydisBranchWidth width_at_last_hop)
{
    ZydisDecoder decoder;
    ZyanStatus status = ZydisDecoderInit(&decoder, mode, stack);
    CHECK(ZYAN_SUCCESS(status), "decoder init failed");

    ZyanU8 current[ZYDIS_MAX_INSTRUCTION_LENGTH];
    ZyanU8 current_len = length;
    memcpy(current, bytes, length);

    ZyanU64 target0 = 0;
    for (ZyanU8 hop = 0; hop + 1 < addr_count; ++hop)
    {
        const ZyanU64 from = addrs[hop];
        const ZyanU64 to = addrs[hop + 1];

        ZydisDecodedInstruction insn;
        ZydisDecodedOperand ops[ZYDIS_MAX_OPERAND_COUNT];
        status = ZydisDecoderDecodeFull(&decoder, current, current_len, &insn, ops);
        CHECK(ZYAN_SUCCESS(status), "hop %u: decode failed: 0x%08X", hop, status);

        const int reloc_op = FindRelocatableOperand(ops, insn.operand_count_visible);
        CHECK(reloc_op >= 0, "hop %u: no relocatable operand", hop);

        ZyanU64 target = 0;
        status = ZydisCalcAbsoluteAddress(&insn, &ops[reloc_op], from, &target);
        CHECK(ZYAN_SUCCESS(status), "hop %u: abs address failed", hop);
        if (hop == 0)
        {
            target0 = target;
        }
        CHECK(target == target0, "hop %u: target drifted: 0x%016" PRIX64 " != 0x%016" PRIX64,
            hop, target, target0);

        ZydisEncoderRequest req;
        status = ZydisEncoderDecodedInstructionToEncoderRequest(&insn, ops,
            insn.operand_count_visible, &req);
        CHECK(ZYAN_SUCCESS(status), "hop %u: request conversion failed", hop);
        req.operands[reloc_op].imm.u = target;
        if (hop == 0 && width_at_hop_1 != ZYDIS_BRANCH_WIDTH_NONE)
        {
            req.branch_width = width_at_hop_1;
            req.branch_type = ZYDIS_BRANCH_TYPE_NONE;
        }
        if (hop + 2 == addr_count && width_at_last_hop != ZYDIS_BRANCH_WIDTH_NONE)
        {
            req.branch_width = width_at_last_hop;
            req.branch_type = ZYDIS_BRANCH_TYPE_NONE;
        }

        ZyanU8 next[ZYDIS_MAX_INSTRUCTION_LENGTH];
        ZyanUSize next_len = sizeof(next);
        status = ZydisEncoderEncodeInstructionAbsolute(&req, next, &next_len, to);
        CHECK(ZYAN_SUCCESS(status), "hop %u: encode failed: 0x%08X", hop, status);

        // Immediately verify the freshly encoded instruction at its new address.
        ZydisDecodedInstruction insn2;
        ZydisDecodedOperand ops2[ZYDIS_MAX_OPERAND_COUNT];
        status = ZydisDecoderDecodeFull(&decoder, next, (ZyanUSize)next_len, &insn2, ops2);
        CHECK(ZYAN_SUCCESS(status), "hop %u: re-decode failed", hop);
        ZyanU64 target2 = 0;
        status = ZydisCalcAbsoluteAddress(&insn2, &ops2[reloc_op], to, &target2);
        CHECK(ZYAN_SUCCESS(status), "hop %u: abs address (re-decoded) failed", hop);
        CHECK(target2 == target0, "hop %u: target mismatch after relocation", hop);
        CHECK(CompareSemantics(&insn, ops, &insn2, ops2, reloc_op),
            "hop %u: semantics changed", hop);

        memcpy(current, next, next_len);
        current_len = (ZyanU8)next_len;
        printf("    hop %u: 0x%016" PRIX64 " -> 0x%016" PRIX64 " (%u bytes), target 0x%016"
            PRIX64 "\n", hop, from, to, (ZyanU32)current_len, target0);
    }

    // The last hop returned to the original address with the original width: the encoding
    // must be byte-identical to the input.
    CHECK(current_len == length && memcmp(current, bytes, length) == 0,
        "round-trip did not reproduce original bytes");
    (void)name;
    return ZYAN_TRUE;
}

static void RunChainCase(const char *name, ZydisMachineMode mode, ZydisStackWidth stack,
    const ZyanU8 *bytes, ZyanU8 length, const ZyanU64 *addrs, ZyanU8 addr_count,
    ZydisBranchWidth width_at_hop_1, ZydisBranchWidth width_at_last_hop)
{
    printf("[%-56s] ", name);
    if (RunChain(name, mode, stack, bytes, length, addrs, addr_count, width_at_hop_1,
            width_at_last_hop))
    {
        printf("  PASS\n");
        ++g_pass_count;
    }
    else
    {
        printf("  FAIL\n");
        ++g_fail_count;
    }
}

/* ============================================================================================== */
/* Test cases                                                                                     */
/* ============================================================================================== */

#define TC64(name, old, new, expect, ...)                                       \
    { name, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64, { __VA_ARGS__ },  \
      (ZyanU8)sizeof((const ZyanU8[]){ __VA_ARGS__ }), old, new, expect,        \
      ZYDIS_BRANCH_WIDTH_NONE, 0 }
#define TC32(name, old, new, expect, ...)                                       \
    { name, ZYDIS_MACHINE_MODE_LEGACY_32, ZYDIS_STACK_WIDTH_32, { __VA_ARGS__ },\
      (ZyanU8)sizeof((const ZyanU8[]){ __VA_ARGS__ }), old, new, expect,        \
      ZYDIS_BRANCH_WIDTH_NONE, 0 }
#define TC16(name, old, new, expect, ...)                                       \
    { name, ZYDIS_MACHINE_MODE_LEGACY_16, ZYDIS_STACK_WIDTH_16, { __VA_ARGS__ },\
      (ZyanU8)sizeof((const ZyanU8[]){ __VA_ARGS__ }), old, new, expect,        \
      ZYDIS_BRANCH_WIDTH_NONE, 0 }

static const TestCase g_tests[] =
{
    /* ---------------- 64-bit mode: relative branches ---------------- */
    TC64("64: jmp rel8 in range",
        0x1000, 0x1080, EXPECT_OK, 0xEB, 0x05),
    TC64("64: jmp rel8 +127 boundary",
        0x1000, 0x1000, EXPECT_OK, 0xEB, 0x7F),
    TC64("64: jmp rel8 -128 boundary",
        0x1100, 0x1100, EXPECT_OK, 0xEB, 0x80),
    TC64("64: jmp rel8 out of range -> explicit error",
        0x1000, 0x2000, EXPECT_FAIL, 0xEB, 0x7F),
    TC64("64: jmp rel32 +2^31-1 boundary",
        0x1000, 0x1000, EXPECT_OK, 0xE9, 0xFB, 0xFF, 0xFF, 0x7F),
    TC64("64: jmp rel32 -2^31 boundary",
        0x90000000, 0x90000000, EXPECT_OK, 0xE9, 0x00, 0x00, 0x00, 0x80),
    TC64("64: jmp rel32 out of range -> explicit error",
        0x1000, 0x100000000, EXPECT_FAIL, 0xE9, 0x00, 0x00, 0x00, 0x00),
    TC64("64: call rel32 in range",
        0x1000, 0x8000, EXPECT_OK, 0xE8, 0x00, 0x00, 0x00, 0x00),
    TC64("64: call rel32 out of range -> explicit error",
        0x1000, 0x100000000, EXPECT_FAIL, 0xE8, 0x00, 0x00, 0x00, 0x00),
    TC64("64: jz rel8 in range",
        0x1000, 0x1040, EXPECT_OK, 0x74, 0x7E),
    TC64("64: jz rel8 out of range -> explicit error",
        0x1000, 0x9000, EXPECT_FAIL, 0x74, 0x7E),
    TC64("64: jnz rel32 in range",
        0x1000, 0x2000, EXPECT_OK, 0x0F, 0x85, 0x78, 0x56, 0x34, 0x12),
    TC64("64: jrcxz rel8 -128 boundary",
        0x1000, 0x1090, EXPECT_OK, 0xE3, 0x10),
    TC64("64: jrcxz rel8 out of range -> explicit error",
        0x1000, 0x2000, EXPECT_FAIL, 0xE3, 0x10),
    TC64("64: jecxz (67h) rel8 -128 boundary",
        0x1000, 0x1090, EXPECT_OK, 0x67, 0xE3, 0x10),
    TC64("64: loop rel8 -128 boundary",
        0x1000, 0x107E, EXPECT_OK, 0xE2, 0xFE),
    TC64("64: loop rel8 out of range -> explicit error",
        0x1000, 0x1080, EXPECT_FAIL, 0xE2, 0xFE),

    /* ---------------- 64-bit mode: RIP-relative memory operands ---------------- */
    TC64("64: mov rax,[rip+0] in range",
        0x1000, 0x2000, EXPECT_OK, 0x48, 0x8B, 0x05, 0x00, 0x00, 0x00, 0x00),
    TC64("64: mov rax,[rip+disp32] +2^31-1 boundary",
        0x1000, 0x1000, EXPECT_OK, 0x48, 0x8B, 0x05, 0xF9, 0xFF, 0xFF, 0x7F),
    TC64("64: mov rax,[rip+disp32] -2^31 boundary",
        0x90000000, 0x90000000, EXPECT_OK, 0x48, 0x8B, 0x05, 0x00, 0x00, 0x00, 0x80),
    TC64("64: mov rax,[rip+disp32] out of range -> explicit error",
        0x1000, 0x190000000, EXPECT_FAIL, 0x48, 0x8B, 0x05, 0x00, 0x00, 0x00, 0x00),
    TC64("64: lea rcx,[rip+disp32] in range",
        0x1000, 0x5000, EXPECT_OK, 0x48, 0x8D, 0x0D, 0x00, 0x10, 0x00, 0x00),
    TC64("64: mov rax,[moffs64] absolute",
        0x1000, 0x2000, EXPECT_OK,
        0x48, 0xA1, 0x78, 0x56, 0x34, 0x12, 0x00, 0x00, 0x00, 0x00),

    /* ---------------- 32-bit mode ---------------- */
    TC32("32: jmp rel8 -128 boundary",
        0x1100, 0x1100, EXPECT_OK, 0xEB, 0x80),
    TC32("32: jmp rel8 out of range -> explicit error",
        0x1000, 0x5000, EXPECT_FAIL, 0xEB, 0x7F),
    TC32("32: jmp rel16 +32767 boundary",
        0x1000, 0x1000, EXPECT_OK, 0x66, 0xE9, 0xFF, 0x7F),
    TC32("32: jmp rel16 -32768 boundary",
        0x10000, 0x10000, EXPECT_OK, 0x66, 0xE9, 0x00, 0x80),
    TC32("32: jmp rel16 out of range -> explicit error",
        0x1000, 0x20000, EXPECT_FAIL, 0x66, 0xE9, 0x00, 0x00),
    TC32("32: jmp rel32 +2^31-1 boundary",
        0x1000, 0x1000, EXPECT_OK, 0xE9, 0xFB, 0xFF, 0xFF, 0x7F),
    TC32("32: call rel32 in range",
        0x1000, 0x8000, EXPECT_OK, 0xE8, 0x00, 0x00, 0x00, 0x00),
    TC32("32: call rel16 in range",
        0x1000, 0x1000, EXPECT_OK, 0x66, 0xE8, 0x00, 0x10),
    TC32("32: jz rel32 in range",
        0x1000, 0x3000, EXPECT_OK, 0x0F, 0x84, 0x00, 0x10, 0x00, 0x00),
    TC32("32: jz rel16 in range",
        0x1000, 0x1000, EXPECT_OK, 0x66, 0x0F, 0x84, 0x00, 0x10),
    TC32("32: jecxz rel8 -128 boundary",
        0x1000, 0x1090, EXPECT_OK, 0xE3, 0x10),
    TC32("32: mov eax,[moffs32] absolute",
        0x1000, 0x2000, EXPECT_OK, 0xA1, 0x78, 0x56, 0x34, 0x12),

    /* ---------------- 16-bit mode ---------------- */
    TC16("16: jmp rel8 +127 boundary",
        0x1000, 0x1000, EXPECT_OK, 0xEB, 0x7F),
    TC16("16: jmp rel8 out of range -> explicit error",
        0x1000, 0x2000, EXPECT_FAIL, 0xEB, 0x7F),
    TC16("16: jmp rel16 +32767 boundary",
        0x1000, 0x1000, EXPECT_OK, 0xE9, 0xFF, 0x7F),
    TC16("16: jmp rel16 -32768 boundary",
        0x9000, 0x9000, EXPECT_OK, 0xE9, 0x00, 0x80),
    TC16("16: jmp rel16 out of range -> explicit error",
        0x1000, 0x9001, EXPECT_FAIL, 0xE9, 0x00, 0x00),
    TC16("16: jmp rel32 (66h) in range",
        0x1000, 0x1000, EXPECT_OK, 0x66, 0xE9, 0x00, 0x00, 0x01, 0x00),
    TC16("16: call rel16 in range",
        0x1000, 0x1000, EXPECT_OK, 0xE8, 0x00, 0x10),
    TC16("16: jz rel8 in range",
        0x1000, 0x1080, EXPECT_OK, 0x74, 0x05),
    TC16("16: jz rel16 in range",
        0x1000, 0x1000, EXPECT_OK, 0x0F, 0x84, 0x00, 0x10),
    TC16("16: jcxz rel8 -128 boundary",
        0x1000, 0x1090, EXPECT_OK, 0xE3, 0x10),
    TC16("16: jecxz (67h) rel8 -128 boundary",
        0x1000, 0x1090, EXPECT_OK, 0x67, 0xE3, 0x10),
    TC16("16: loopne rel8 in range",
        0x1000, 0x1000, EXPECT_OK, 0xE0, 0x10),
    TC16("16: mov ax,[moffs16] absolute",
        0x1000, 0x2000, EXPECT_OK, 0xA1, 0x34, 0x12),
    // 16-bit IP arithmetic wraps at 64K; the decoder reports the wrapped 16-bit target, so a
    // 64-bit displacement computation cannot represent it. The encoder must reject this
    // explicitly instead of emitting a truncated/wrong displacement.
    TC16("16: jmp rel16 IP-wrap -> explicit error",
        0xFFF0, 0xFFF0, EXPECT_FAIL, 0xE9, 0x20, 0x00),
};

/* Cases that force a wider branch width: the re-encoded instruction is longer than the
 * decoded one, so the displacement field moves -- the absolute target must still be exact. */
static const TestCase g_widen_tests[] =
{
    { "64: widen jmp rel8 -> rel32 (length 2->5)",
      ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64,
      { 0xEB, 0x7F }, 2, 0x1000, 0x2000, EXPECT_OK, ZYDIS_BRANCH_WIDTH_32, 5 },
    { "64: widen jz rel8 -> rel32 (length 2->6)",
      ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64,
      { 0x74, 0x7E }, 2, 0x1000, 0x9000, EXPECT_OK, ZYDIS_BRANCH_WIDTH_32, 6 },
    { "32: widen jmp rel16 -> rel32 (length 4->5)",
      ZYDIS_MACHINE_MODE_LEGACY_32, ZYDIS_STACK_WIDTH_32,
      { 0x66, 0xE9, 0x00, 0x00 }, 4, 0x1000, 0x20000, EXPECT_OK, ZYDIS_BRANCH_WIDTH_32, 5 },
    { "32: widen jmp rel8 -> rel32 (length 2->5)",
      ZYDIS_MACHINE_MODE_LEGACY_32, ZYDIS_STACK_WIDTH_32,
      { 0xEB, 0x7F }, 2, 0x1000, 0x5000, EXPECT_OK, ZYDIS_BRANCH_WIDTH_32, 5 },
    { "16: widen jmp rel8 -> rel16 (length 2->3)",
      ZYDIS_MACHINE_MODE_LEGACY_16, ZYDIS_STACK_WIDTH_16,
      { 0xEB, 0x7F }, 2, 0x1000, 0x2000, EXPECT_OK, ZYDIS_BRANCH_WIDTH_16, 3 },
    { "16: widen jmp rel16 -> rel32 (length 3->6)",
      ZYDIS_MACHINE_MODE_LEGACY_16, ZYDIS_STACK_WIDTH_16,
      { 0xE9, 0x00, 0x00 }, 3, 0x1000, 0x20000, EXPECT_OK, ZYDIS_BRANCH_WIDTH_32, 6 },
};

/* ============================================================================================== */
/* Entry point                                                                                    */
/* ============================================================================================== */

int main(void)
{
    for (ZyanUSize i = 0; i < ZYAN_ARRAY_LENGTH(g_tests); ++i)
    {
        RunCase(&g_tests[i]);
    }
    for (ZyanUSize i = 0; i < ZYAN_ARRAY_LENGTH(g_widen_tests); ++i)
    {
        RunCase(&g_widen_tests[i]);
    }

    // Chained relocation: the same instruction is relocated through several addresses and
    // back to its original location; the absolute target must survive every hop and the
    // final encoding must be byte-identical to the original.
    {
        static const ZyanU8 jmp32[] = { 0xE9, 0x00, 0x10, 0x00, 0x00 };
        static const ZyanU64 addrs[] = { 0x1000, 0x8000, 0x40000, 0x1000 };
        RunChainCase("chain: jmp rel32 through 3 relocations and back",
            ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64, jmp32, sizeof(jmp32),
            addrs, ZYAN_ARRAY_LENGTH(addrs), ZYDIS_BRANCH_WIDTH_NONE, ZYDIS_BRANCH_WIDTH_NONE);
    }
    {
        // Same, but the first hop widens rel8 -> rel32 (length change mid-chain) and the
        // last hop narrows back to rel8.
        static const ZyanU8 jmp8[] = { 0xEB, 0x05 };
        static const ZyanU64 addrs[] = { 0x1000, 0x80000, 0x40000, 0x1000 };
        RunChainCase("chain: jmp rel8 widened mid-chain, narrowed back",
            ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64, jmp8, sizeof(jmp8),
            addrs, ZYAN_ARRAY_LENGTH(addrs), ZYDIS_BRANCH_WIDTH_32, ZYDIS_BRANCH_WIDTH_8);
    }
    {
        static const ZyanU8 call32[] = { 0xE8, 0x00, 0x10, 0x00, 0x00 };
        static const ZyanU64 addrs[] = { 0x1000, 0x9000, 0x1000 };
        RunChainCase("chain: call rel32 there and back (32-bit)",
            ZYDIS_MACHINE_MODE_LEGACY_32, ZYDIS_STACK_WIDTH_32, call32, sizeof(call32),
            addrs, ZYAN_ARRAY_LENGTH(addrs), ZYDIS_BRANCH_WIDTH_NONE, ZYDIS_BRANCH_WIDTH_NONE);
    }
    {
        static const ZyanU8 jmp16[] = { 0xE9, 0x00, 0x10 };
        static const ZyanU64 addrs[] = { 0x1000, 0x4000, 0x1000 };
        RunChainCase("chain: jmp rel16 there and back (16-bit)",
            ZYDIS_MACHINE_MODE_LEGACY_16, ZYDIS_STACK_WIDTH_16, jmp16, sizeof(jmp16),
            addrs, ZYAN_ARRAY_LENGTH(addrs), ZYDIS_BRANCH_WIDTH_NONE, ZYDIS_BRANCH_WIDTH_NONE);
    }

    printf("\n%d passed, %d failed\n", g_pass_count, g_fail_count);
    return g_fail_count == 0 ? 0 : 1;
}
