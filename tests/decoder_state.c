/***************************************************************************************************

  Zydis Decoder State Unit Test

  Verifies that a single, reused `ZydisDecoder` instance produces results that depend only on
  its *current* configuration (machine mode, stack width, decoder modes) and the *current* input
  buffer:

  1. Machine-mode / stack-width switching on one decoder instance (16/32/64-bit), including
     mode-specific interpretation of the same byte stream (REX byte vs. one-byte opcode) and
     effective address-width results.
  2. Decoder-mode (decode option) toggling between calls (LZCNT, AMD branch semantics) with
     distinguishable outcomes per option value and full restoration after toggling back.
  3. Illegal prefixes (illegal LOCK, illegal REX, instruction too long) and truncated
     instructions (NO_MORE_DATA), including the 15-byte maximum-length boundary.
  4. Failure cleanup: a failed decode must not leak metadata from the previous instruction,
     must not corrupt the decoder for subsequent calls, must reject the same bad input stably,
     and must reject different bad inputs with distinguishable status codes.
  5. Cross-call independence: results after failures / mode switches are field-for-field
     identical to results produced by a freshly initialized decoder.

***************************************************************************************************/

#include <Zydis/Zydis.h>

#include <stdio.h>
#include <string.h>

/* ============================================================================================== */
/* Test framework                                                                                 */
/* ============================================================================================== */

static int g_checks = 0;
static int g_failures = 0;

#define CHECK(cond, msg)                                                                        \
    do                                                                                          \
    {                                                                                           \
        ++g_checks;                                                                             \
        if (!(cond))                                                                            \
        {                                                                                       \
            ++g_failures;                                                                       \
            printf("FAIL [%s:%d]: %s\n", __FILE__, __LINE__, msg);                              \
        }                                                                                       \
    } while (0)

#define CHECK_STATUS_SUCCESS(status, msg)                                                       \
    do                                                                                          \
    {                                                                                           \
        ++g_checks;                                                                             \
        if (!ZYAN_SUCCESS(status))                                                              \
        {                                                                                       \
            ++g_failures;                                                                       \
            printf("FAIL [%s:%d]: %s (status = 0x%08X)\n", __FILE__, __LINE__, msg,             \
                (unsigned)(status));                                                            \
        }                                                                                       \
    } while (0)

#define CHECK_STATUS_EQ(status, expected, msg)                                                  \
    do                                                                                          \
    {                                                                                           \
        ++g_checks;                                                                             \
        if ((status) != (expected))                                                             \
        {                                                                                       \
            ++g_failures;                                                                       \
            printf("FAIL [%s:%d]: %s (status = 0x%08X, expected = 0x%08X)\n", __FILE__,         \
                __LINE__, msg, (unsigned)(status), (unsigned)(expected));                       \
        }                                                                                       \
    } while (0)

/* ============================================================================================== */
/* Helpers                                                                                        */
/* ============================================================================================== */

typedef struct DecodeResult_
{
    ZyanStatus status;
    ZydisDecodedInstruction instruction;
    ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];
} DecodeResult;

/**
 * Decodes a single instruction with `ZydisDecoderDecodeFull` into a poisoned result struct.
 *
 * The output struct is deliberately filled with a garbage pattern before decoding so that any
 * field the decoder fails to (re)initialize is detectable and cannot accidentally inherit data
 * from a previous decode stored in the same memory.
 */
static void DecodeFull(const ZydisDecoder* decoder, const void* buffer, ZyanUSize length,
    DecodeResult* result)
{
    memset(result, 0xAA, sizeof(*result));
    result->status = ZydisDecoderDecodeFull(decoder, buffer, length, &result->instruction,
        result->operands);
}

/**
 * Compares the semantic fields of two decode results (instruction + operands).
 *
 * Used to prove that a decode performed after failures, mode switches or option toggles is
 * identical to the same decode performed on a pristine decoder.
 */
static ZyanBool ResultsEqual(const DecodeResult* a, const DecodeResult* b)
{
    const ZydisDecodedInstruction* ia = &a->instruction;
    const ZydisDecodedInstruction* ib = &b->instruction;

    if ((a->status != b->status) ||
        (ia->machine_mode != ib->machine_mode) ||
        (ia->mnemonic != ib->mnemonic) ||
        (ia->length != ib->length) ||
        (ia->encoding != ib->encoding) ||
        (ia->stack_width != ib->stack_width) ||
        (ia->operand_width != ib->operand_width) ||
        (ia->address_width != ib->address_width) ||
        (ia->operand_count != ib->operand_count) ||
        (ia->operand_count_visible != ib->operand_count_visible) ||
        (ia->attributes != ib->attributes))
    {
        return ZYAN_FALSE;
    }

    for (ZyanU8 i = 0; i < ia->operand_count; ++i)
    {
        const ZydisDecodedOperand* oa = &a->operands[i];
        const ZydisDecodedOperand* ob = &b->operands[i];

        if ((oa->type != ob->type) ||
            (oa->visibility != ob->visibility) ||
            (oa->actions != ob->actions) ||
            (oa->encoding != ob->encoding) ||
            (oa->size != ob->size) ||
            (oa->element_type != ob->element_type) ||
            (oa->element_size != ob->element_size) ||
            (oa->element_count != ob->element_count) ||
            (oa->attributes != ob->attributes))
        {
            return ZYAN_FALSE;
        }

        switch (oa->type)
        {
        case ZYDIS_OPERAND_TYPE_REGISTER:
            if (oa->reg.value != ob->reg.value)
            {
                return ZYAN_FALSE;
            }
            break;
        case ZYDIS_OPERAND_TYPE_MEMORY:
            if ((oa->mem.type != ob->mem.type) ||
                (oa->mem.segment != ob->mem.segment) ||
                (oa->mem.base != ob->mem.base) ||
                (oa->mem.index != ob->mem.index) ||
                (oa->mem.scale != ob->mem.scale) ||
                (oa->mem.disp.value != ob->mem.disp.value) ||
                (oa->mem.disp.size != ob->mem.disp.size))
            {
                return ZYAN_FALSE;
            }
            break;
        case ZYDIS_OPERAND_TYPE_POINTER:
            if ((oa->ptr.segment != ob->ptr.segment) || (oa->ptr.offset != ob->ptr.offset))
            {
                return ZYAN_FALSE;
            }
            break;
        case ZYDIS_OPERAND_TYPE_IMMEDIATE:
            if ((oa->imm.is_signed != ob->imm.is_signed) ||
                (oa->imm.is_relative != ob->imm.is_relative) ||
                (oa->imm.value.u != ob->imm.value.u) ||
                (oa->imm.size != ob->imm.size))
            {
                return ZYAN_FALSE;
            }
            break;
        default:
            break;
        }
    }

    return ZYAN_TRUE;
}

/* ============================================================================================== */
/* 1. Machine-mode / stack-width switching on a single decoder instance                           */
/* ============================================================================================== */

static void TestMachineModeSwitching(void)
{
    printf("== TestMachineModeSwitching\n");

    ZydisDecoder decoder;
    DecodeResult result;

    /* `48 89 D8` -- REX.W + MOV in 64-bit mode, one-byte DEC opcodes otherwise. */
    static const ZyanU8 code[] = { 0x48, 0x89, 0xD8 };

    /* 64-bit mode: REX.W MOV r64, r64 */
    CHECK_STATUS_SUCCESS(ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64,
        ZYDIS_STACK_WIDTH_64), "init 64-bit");
    DecodeFull(&decoder, code, sizeof(code), &result);
    CHECK_STATUS_SUCCESS(result.status, "64-bit: decode 48 89 D8");
    CHECK(result.instruction.mnemonic == ZYDIS_MNEMONIC_MOV, "64-bit: mnemonic is MOV");
    CHECK(result.instruction.length == 3, "64-bit: length is 3");
    CHECK(result.instruction.operand_width == 64, "64-bit: operand width is 64");
    CHECK(result.instruction.address_width == 64, "64-bit: address width is 64");
    CHECK(result.instruction.stack_width == 64, "64-bit: stack width is 64");
    CHECK(result.instruction.machine_mode == ZYDIS_MACHINE_MODE_LONG_64,
        "64-bit: machine mode reported as LONG_64");
    CHECK(result.instruction.attributes & ZYDIS_ATTRIB_HAS_REX, "64-bit: REX attribute set");
    CHECK(result.operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
          result.operands[0].reg.value == ZYDIS_REGISTER_RAX, "64-bit: dst is RAX");
    CHECK(result.operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER &&
          result.operands[1].reg.value == ZYDIS_REGISTER_RBX, "64-bit: src is RBX");

    /* Re-initialize the SAME decoder instance for 32-bit: `48` is now `DEC EAX`. */
    CHECK_STATUS_SUCCESS(ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LEGACY_32,
        ZYDIS_STACK_WIDTH_32), "re-init 32-bit");
    DecodeFull(&decoder, code, sizeof(code), &result);
    CHECK_STATUS_SUCCESS(result.status, "32-bit: decode 48 89 D8");
    CHECK(result.instruction.mnemonic == ZYDIS_MNEMONIC_DEC, "32-bit: mnemonic is DEC");
    CHECK(result.instruction.length == 1, "32-bit: length is 1 (no REX state leaked)");
    CHECK(result.instruction.operand_width == 32, "32-bit: operand width is 32");
    CHECK(result.instruction.address_width == 32, "32-bit: address width is 32");
    CHECK(result.instruction.machine_mode == ZYDIS_MACHINE_MODE_LEGACY_32,
        "32-bit: machine mode reported as LEGACY_32");
    CHECK(!(result.instruction.attributes & ZYDIS_ATTRIB_HAS_REX),
        "32-bit: no REX attribute leaked from 64-bit decode");
    CHECK(result.operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
          result.operands[0].reg.value == ZYDIS_REGISTER_EAX, "32-bit: operand is EAX");

    /* Re-initialize the SAME decoder instance for 16-bit: `48` is `DEC AX`. */
    CHECK_STATUS_SUCCESS(ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LEGACY_16,
        ZYDIS_STACK_WIDTH_16), "re-init 16-bit");
    DecodeFull(&decoder, code, sizeof(code), &result);
    CHECK_STATUS_SUCCESS(result.status, "16-bit: decode 48 89 D8");
    CHECK(result.instruction.mnemonic == ZYDIS_MNEMONIC_DEC, "16-bit: mnemonic is DEC");
    CHECK(result.instruction.length == 1, "16-bit: length is 1");
    CHECK(result.instruction.operand_width == 16, "16-bit: operand width is 16");
    CHECK(result.instruction.address_width == 16, "16-bit: address width is 16");
    CHECK(result.operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
          result.operands[0].reg.value == ZYDIS_REGISTER_AX, "16-bit: operand is AX");

    /* Switching back to 64-bit must reproduce the original result exactly. */
    {
        DecodeResult first, again;
        CHECK_STATUS_SUCCESS(ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64,
            ZYDIS_STACK_WIDTH_64), "re-init 64-bit");
        DecodeFull(&decoder, code, sizeof(code), &first);

        {
            ZydisDecoder pristine;
            CHECK_STATUS_SUCCESS(ZydisDecoderInit(&pristine, ZYDIS_MACHINE_MODE_LONG_64,
                ZYDIS_STACK_WIDTH_64), "init pristine 64-bit");
            DecodeFull(&pristine, code, sizeof(code), &again);
        }
        CHECK(ResultsEqual(&first, &again),
            "64-bit result after mode round-trip equals pristine decoder result");
    }
}

/* ============================================================================================== */
/* 2. Effective address width per machine mode                                                    */
/* ============================================================================================== */

static void TestAddressWidthSwitching(void)
{
    printf("== TestAddressWidthSwitching\n");

    ZydisDecoder decoder;
    DecodeResult result;

    /* `8B 06 34 12` -- MOV r, [mem]; the ModRM byte selects a different addressing
     * form (and thus a different instruction length) in every address-width mode. */
    static const ZyanU8 code[] = { 0x8B, 0x06, 0x34, 0x12 };

    CHECK_STATUS_SUCCESS(ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LEGACY_16,
        ZYDIS_STACK_WIDTH_16), "init 16-bit");
    DecodeFull(&decoder, code, sizeof(code), &result);
    CHECK_STATUS_SUCCESS(result.status, "16-bit: decode 8B 06 34 12");
    CHECK(result.instruction.mnemonic == ZYDIS_MNEMONIC_MOV, "16-bit: mnemonic is MOV");
    CHECK(result.instruction.length == 4, "16-bit: length is 4 (disp16)");
    CHECK(result.instruction.address_width == 16, "16-bit: address width is 16");
    CHECK(result.operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY &&
          result.operands[1].mem.base == ZYDIS_REGISTER_NONE &&
          result.operands[1].mem.disp.value == 0x1234 &&
          result.operands[1].mem.disp.size == 16, "16-bit: [disp16=0x1234]");

    CHECK_STATUS_SUCCESS(ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LEGACY_32,
        ZYDIS_STACK_WIDTH_32), "re-init 32-bit");
    DecodeFull(&decoder, code, sizeof(code), &result);
    CHECK_STATUS_SUCCESS(result.status, "32-bit: decode 8B 06 34 12");
    CHECK(result.instruction.length == 2, "32-bit: length is 2 (no disp consumed)");
    CHECK(result.instruction.address_width == 32, "32-bit: address width is 32");
    CHECK(result.operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY &&
          result.operands[1].mem.base == ZYDIS_REGISTER_ESI, "32-bit: [ESI]");

    CHECK_STATUS_SUCCESS(ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64,
        ZYDIS_STACK_WIDTH_64), "re-init 64-bit");
    DecodeFull(&decoder, code, sizeof(code), &result);
    CHECK_STATUS_SUCCESS(result.status, "64-bit: decode 8B 06 34 12");
    CHECK(result.instruction.length == 2, "64-bit: length is 2");
    CHECK(result.instruction.address_width == 64, "64-bit: address width is 64");
    CHECK(result.operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY &&
          result.operands[1].mem.base == ZYDIS_REGISTER_RSI, "64-bit: [RSI]");
}

/* ============================================================================================== */
/* 3. Decoder-mode (decode option) toggling between calls                                         */
/* ============================================================================================== */

static void TestDecoderModeToggling(void)
{
    printf("== TestDecoderModeToggling\n");

    ZydisDecoder decoder;
    DecodeResult result;

    CHECK_STATUS_SUCCESS(ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64,
        ZYDIS_STACK_WIDTH_64), "init 64-bit");

    /* `F3 0F BD C0` -- LZCNT (mode on, default) vs. BSR (mode off). */
    static const ZyanU8 lzcnt[] = { 0xF3, 0x0F, 0xBD, 0xC0 };

    DecodeFull(&decoder, lzcnt, sizeof(lzcnt), &result);
    CHECK_STATUS_SUCCESS(result.status, "LZCNT mode on: decode ok");
    CHECK(result.instruction.mnemonic == ZYDIS_MNEMONIC_LZCNT,
        "LZCNT mode on: mnemonic is LZCNT");

    CHECK_STATUS_SUCCESS(ZydisDecoderEnableMode(&decoder, ZYDIS_DECODER_MODE_LZCNT, ZYAN_FALSE),
        "disable LZCNT mode");
    DecodeFull(&decoder, lzcnt, sizeof(lzcnt), &result);
    CHECK_STATUS_SUCCESS(result.status, "LZCNT mode off: decode ok");
    CHECK(result.instruction.mnemonic == ZYDIS_MNEMONIC_BSR,
        "LZCNT mode off: mnemonic is BSR");

    /* Toggling back must fully restore the previous behavior (no sticky option state). */
    CHECK_STATUS_SUCCESS(ZydisDecoderEnableMode(&decoder, ZYDIS_DECODER_MODE_LZCNT, ZYAN_TRUE),
        "re-enable LZCNT mode");
    DecodeFull(&decoder, lzcnt, sizeof(lzcnt), &result);
    CHECK_STATUS_SUCCESS(result.status, "LZCNT mode re-enabled: decode ok");
    CHECK(result.instruction.mnemonic == ZYDIS_MNEMONIC_LZCNT,
        "LZCNT mode re-enabled: mnemonic is LZCNT again");

    /* `66 E9 ...` -- near JMP. Intel semantics (default) ignore the 0x66 prefix in 64-bit
     * mode and decode a rel32 immediate; AMD semantics honor it and decode rel16. The same
     * buffer therefore yields different lengths, operand widths and immediates -- and for a
     * short buffer even a different success/failure conclusion. */
    static const ZyanU8 jmp_full[] = { 0x66, 0xE9, 0x34, 0x12, 0x00, 0x00, 0x90 };
    static const ZyanU8 jmp_short[] = { 0x66, 0xE9, 0x34, 0x12 };

    DecodeFull(&decoder, jmp_full, sizeof(jmp_full), &result);
    CHECK_STATUS_SUCCESS(result.status, "Intel branches: decode ok");
    CHECK(result.instruction.mnemonic == ZYDIS_MNEMONIC_JMP, "Intel branches: JMP");
    CHECK(result.instruction.length == 6, "Intel branches: length is 6 (0x66 ignored, rel32)");
    CHECK(result.instruction.operand_width == 64, "Intel branches: operand width 64");

    DecodeFull(&decoder, jmp_short, sizeof(jmp_short), &result);
    CHECK_STATUS_EQ(result.status, ZYDIS_STATUS_NO_MORE_DATA,
        "Intel branches: short buffer is truncated (rel32 does not fit)");

    CHECK_STATUS_SUCCESS(ZydisDecoderEnableMode(&decoder, ZYDIS_DECODER_MODE_AMD_BRANCHES,
        ZYAN_TRUE), "enable AMD branch mode");
    DecodeFull(&decoder, jmp_full, sizeof(jmp_full), &result);
    CHECK_STATUS_SUCCESS(result.status, "AMD branches: decode ok");
    CHECK(result.instruction.length == 4, "AMD branches: length is 4 (rel16)");
    CHECK(result.instruction.operand_width == 16, "AMD branches: operand width 16");

    DecodeFull(&decoder, jmp_short, sizeof(jmp_short), &result);
    CHECK_STATUS_SUCCESS(result.status, "AMD branches: short buffer now decodes");
    CHECK(result.instruction.length == 4, "AMD branches: short buffer length is 4");
    CHECK(result.operands[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE &&
          result.operands[0].imm.value.u == 0x1234, "AMD branches: imm16 = 0x1234");

    /* Disabling the mode again must restore Intel semantics exactly. */
    CHECK_STATUS_SUCCESS(ZydisDecoderEnableMode(&decoder, ZYDIS_DECODER_MODE_AMD_BRANCHES,
        ZYAN_FALSE), "disable AMD branch mode");
    DecodeFull(&decoder, jmp_short, sizeof(jmp_short), &result);
    CHECK_STATUS_EQ(result.status, ZYDIS_STATUS_NO_MORE_DATA,
        "Intel branches restored: short buffer truncated again");
}

/* ============================================================================================== */
/* 4. Illegal prefixes and truncated instructions                                                 */
/* ============================================================================================== */

static void TestIllegalPrefixesAndTruncation(void)
{
    printf("== TestIllegalPrefixesAndTruncation\n");

    ZydisDecoder decoder;
    DecodeResult result;

    CHECK_STATUS_SUCCESS(ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64,
        ZYDIS_STACK_WIDTH_64), "init 64-bit");

    /* Illegal LOCK prefix: `F0 90` (LOCK NOP) -- LOCK is only allowed for read-modify-write
     * instructions with a memory destination. */
    {
        static const ZyanU8 code[] = { 0xF0, 0x90 };
        DecodeFull(&decoder, code, sizeof(code), &result);
        CHECK_STATUS_EQ(result.status, ZYDIS_STATUS_ILLEGAL_LOCK, "LOCK NOP rejected");
    }

    /* Illegal REX: `48 C5 F8 77` -- a REX prefix in front of a VEX instruction. */
    {
        static const ZyanU8 code[] = { 0x48, 0xC5, 0xF8, 0x77 };
        DecodeFull(&decoder, code, sizeof(code), &result);
        CHECK_STATUS_EQ(result.status, ZYDIS_STATUS_ILLEGAL_REX,
            "REX prefix before VEX rejected");
    }

    /* Illegal legacy prefix: `66 C5 F8 77` -- a 0x66 prefix in front of a VEX instruction. */
    {
        static const ZyanU8 code[] = { 0x66, 0xC5, 0xF8, 0x77 };
        DecodeFull(&decoder, code, sizeof(code), &result);
        CHECK_STATUS_EQ(result.status, ZYDIS_STATUS_ILLEGAL_LEGACY_PFX,
            "legacy prefix before VEX rejected");
    }

    /* Instruction too long: 14 redundant prefixes + 2-byte instruction = 16 bytes. */
    {
        ZyanU8 code[16];
        memset(code, 0x66, 14);
        code[14] = 0x89;
        code[15] = 0xD8;
        DecodeFull(&decoder, code, sizeof(code), &result);
        CHECK_STATUS_EQ(result.status, ZYDIS_STATUS_INSTRUCTION_TOO_LONG,
            "16-byte instruction rejected");
    }

    /* Boundary: exactly 15 bytes (13 redundant prefixes + 2-byte instruction) is the maximum
     * legal instruction length and must still decode. */
    {
        ZyanU8 code[15];
        memset(code, 0x66, 13);
        code[13] = 0x89;
        code[14] = 0xD8;
        DecodeFull(&decoder, code, sizeof(code), &result);
        CHECK_STATUS_SUCCESS(result.status, "15-byte instruction accepted");
        CHECK(result.instruction.length == 15, "15-byte instruction length is 15");
        CHECK(result.instruction.mnemonic == ZYDIS_MNEMONIC_MOV,
            "15-byte instruction is MOV");
    }

    /* Truncated instructions of increasing complexity. */
    {
        static const ZyanU8 map_escape[] = { 0x0F };
        DecodeFull(&decoder, map_escape, sizeof(map_escape), &result);
        CHECK_STATUS_EQ(result.status, ZYDIS_STATUS_NO_MORE_DATA,
            "lone 0F map escape rejected as truncated");
    }
    {
        static const ZyanU8 missing_modrm[] = { 0x48, 0x89 };
        DecodeFull(&decoder, missing_modrm, sizeof(missing_modrm), &result);
        CHECK_STATUS_EQ(result.status, ZYDIS_STATUS_NO_MORE_DATA,
            "missing ModRM byte rejected as truncated");
    }
    {
        static const ZyanU8 short_imm[] = { 0xE8, 0x01, 0x02 };
        DecodeFull(&decoder, short_imm, sizeof(short_imm), &result);
        CHECK_STATUS_EQ(result.status, ZYDIS_STATUS_NO_MORE_DATA,
            "truncated rel32 immediate rejected");
    }

    /* Buffer-length boundary: the same CALL decodes with exactly 5 bytes and fails with 4. */
    {
        static const ZyanU8 call[] = { 0xE8, 0x01, 0x02, 0x03, 0x04 };
        DecodeFull(&decoder, call, sizeof(call), &result);
        CHECK_STATUS_SUCCESS(result.status, "CALL with exact buffer decodes");
        CHECK(result.instruction.length == 5, "CALL length is 5");
        CHECK(result.instruction.mnemonic == ZYDIS_MNEMONIC_CALL, "CALL mnemonic");

        DecodeFull(&decoder, call, sizeof(call) - 1, &result);
        CHECK_STATUS_EQ(result.status, ZYDIS_STATUS_NO_MORE_DATA,
            "CALL with one byte less rejected as truncated");
    }
}

/* ============================================================================================== */
/* 5. Failure cleanup and cross-call state                                                        */
/* ============================================================================================== */

static void TestFailureCleanup(void)
{
    printf("== TestFailureCleanup\n");

    ZydisDecoder decoder;
    CHECK_STATUS_SUCCESS(ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64,
        ZYDIS_STACK_WIDTH_64), "init 64-bit");

    static const ZyanU8 code_a[] = { 0x48, 0x89, 0xD8 }; /* MOV RAX, RBX  */
    static const ZyanU8 code_b[] = { 0x53 };             /* PUSH RBX      */
    static const ZyanU8 bad_lock[] = { 0xF0, 0x90 };     /* LOCK NOP      */
    static const ZyanU8 bad_trunc[] = { 0x0F };          /* truncated     */

    DecodeResult a_before, a_after, b_reused, b_pristine;

    /* Establish a baseline for instruction A. */
    DecodeFull(&decoder, code_a, sizeof(code_a), &a_before);
    CHECK_STATUS_SUCCESS(a_before.status, "baseline decode of A");

    /* Fail with an illegal LOCK prefix. The failed call must not corrupt the decoder. */
    {
        DecodeResult failure;
        DecodeFull(&decoder, bad_lock, sizeof(bad_lock), &failure);
        CHECK_STATUS_EQ(failure.status, ZYDIS_STATUS_ILLEGAL_LOCK, "illegal LOCK fails");
    }

    /* Decoding B after the failure must be field-for-field identical to decoding B on a
     * freshly initialized decoder -- no metadata of A or of the failed instruction may leak. */
    DecodeFull(&decoder, code_b, sizeof(code_b), &b_reused);
    CHECK_STATUS_SUCCESS(b_reused.status, "decode of B after failure");
    {
        ZydisDecoder pristine;
        CHECK_STATUS_SUCCESS(ZydisDecoderInit(&pristine, ZYDIS_MACHINE_MODE_LONG_64,
            ZYDIS_STACK_WIDTH_64), "init pristine decoder");
        DecodeFull(&pristine, code_b, sizeof(code_b), &b_pristine);
    }
    CHECK_STATUS_SUCCESS(b_pristine.status, "decode of B on pristine decoder");
    CHECK(ResultsEqual(&b_reused, &b_pristine),
        "B after failure equals B on pristine decoder (no leaked state)");

    /* Re-decoding A must reproduce the baseline exactly (decoder config not corrupted). */
    DecodeFull(&decoder, code_a, sizeof(code_a), &a_after);
    CHECK(ResultsEqual(&a_before, &a_after),
        "A after failure equals baseline A (decoder config intact)");

    /* Stable rejection: the same invalid input must fail with the same status every time,
     * independent of what was decoded (or failed) before. */
    for (int i = 0; i < 3; ++i)
    {
        DecodeResult failure;
        DecodeFull(&decoder, bad_lock, sizeof(bad_lock), &failure);
        CHECK_STATUS_EQ(failure.status, ZYDIS_STATUS_ILLEGAL_LOCK,
            "repeated illegal LOCK rejected identically");
    }

    /* Distinguishable rejection: different invalid inputs must produce different,
     * well-defined status codes. */
    {
        DecodeResult f1, f2, f3;
        ZyanU8 too_long[16];
        memset(too_long, 0x66, 14);
        too_long[14] = 0x89;
        too_long[15] = 0xD8;

        DecodeFull(&decoder, bad_lock, sizeof(bad_lock), &f1);
        DecodeFull(&decoder, bad_trunc, sizeof(bad_trunc), &f2);
        DecodeFull(&decoder, too_long, sizeof(too_long), &f3);

        CHECK(ZYAN_FAILED(f1.status) && ZYAN_FAILED(f2.status) && ZYAN_FAILED(f3.status),
            "all invalid inputs fail");
        CHECK(f1.status != f2.status && f1.status != f3.status && f2.status != f3.status,
            "invalid inputs are rejected with distinguishable status codes");
    }

    /* A valid instruction directly after a run of failures must still decode correctly. */
    {
        DecodeResult after_failures;
        DecodeFull(&decoder, code_b, sizeof(code_b), &after_failures);
        CHECK(ResultsEqual(&after_failures, &b_pristine),
            "valid decode after failure run equals pristine result");
    }

    /* Operand-array cleanup: decoding an instruction with fewer operands must zero the
     * operand slots used by the previous, larger instruction. */
    {
        static const ZyanU8 nop[] = { 0x90 };
        DecodeResult wide, narrow;

        DecodeFull(&decoder, code_a, sizeof(code_a), &wide);
        CHECK(wide.instruction.operand_count >= 2, "MOV has at least 2 operands");

        /* Reuse the exact same result memory for the NOP decode. */
        narrow = wide;
        narrow.status = ZydisDecoderDecodeFull(&decoder, nop, sizeof(nop),
            &narrow.instruction, narrow.operands);
        CHECK_STATUS_SUCCESS(narrow.status, "NOP decodes");
        CHECK(narrow.instruction.operand_count == 0, "NOP has no operands");
        {
            ZydisDecodedOperand zeroed[ZYDIS_MAX_OPERAND_COUNT];
            memset(zeroed, 0, sizeof(zeroed));
            CHECK(memcmp(narrow.operands, zeroed, sizeof(zeroed)) == 0,
                "excess operand slots are zeroed after decode with fewer operands");
        }
    }
}

/* ============================================================================================== */
/* 6. Cross-mode state isolation                                                                  */
/* ============================================================================================== */

static void TestCrossModeStateIsolation(void)
{
    printf("== TestCrossModeStateIsolation\n");

    ZydisDecoder decoder;
    DecodeResult result;

    /* `40` is a REX prefix in 64-bit mode (and thus truncated without an opcode byte) but a
     * complete one-byte `INC EAX` instruction in 32-bit mode. The conclusion must follow the
     * *current* mode only. */
    static const ZyanU8 rex_or_inc[] = { 0x40 };

    CHECK_STATUS_SUCCESS(ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64,
        ZYDIS_STACK_WIDTH_64), "init 64-bit");
    DecodeFull(&decoder, rex_or_inc, sizeof(rex_or_inc), &result);
    CHECK_STATUS_EQ(result.status, ZYDIS_STATUS_NO_MORE_DATA,
        "64-bit: lone REX prefix is truncated");

    CHECK_STATUS_SUCCESS(ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LEGACY_32,
        ZYDIS_STACK_WIDTH_32), "re-init 32-bit");
    DecodeFull(&decoder, rex_or_inc, sizeof(rex_or_inc), &result);
    CHECK_STATUS_SUCCESS(result.status, "32-bit: 40 decodes as INC");
    CHECK(result.instruction.mnemonic == ZYDIS_MNEMONIC_INC, "32-bit: mnemonic is INC");
    CHECK(result.instruction.length == 1, "32-bit: length is 1");
    CHECK(!(result.instruction.attributes & ZYDIS_ATTRIB_HAS_REX),
        "32-bit: no REX attribute leaked");

    /* Back in 64-bit mode the byte must again be treated as a prefix. */
    CHECK_STATUS_SUCCESS(ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64,
        ZYDIS_STACK_WIDTH_64), "re-init 64-bit");
    DecodeFull(&decoder, rex_or_inc, sizeof(rex_or_inc), &result);
    CHECK_STATUS_EQ(result.status, ZYDIS_STATUS_NO_MORE_DATA,
        "64-bit again: lone REX prefix is truncated");

    /* An instruction decoded in one mode must not leave prefix/REX state behind that changes
     * the decode of the next instruction after a mode switch. Decode a REX.W instruction in
     * 64-bit mode, switch to 16-bit, and decode a plain opcode: the result must equal the
     * result from a decoder that never saw 64-bit mode. */
    {
        static const ZyanU8 rex_mov[] = { 0x48, 0x89, 0xD8 };
        static const ZyanU8 inc_ax[] = { 0x40 };
        DecodeResult reused, pristine;

        DecodeFull(&decoder, rex_mov, sizeof(rex_mov), &result);
        CHECK_STATUS_SUCCESS(result.status, "64-bit: REX.W MOV decodes");
        CHECK(result.instruction.attributes & ZYDIS_ATTRIB_HAS_REX, "64-bit: REX present");

        CHECK_STATUS_SUCCESS(ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LEGACY_16,
            ZYDIS_STACK_WIDTH_16), "re-init 16-bit");
        DecodeFull(&decoder, inc_ax, sizeof(inc_ax), &reused);
        CHECK_STATUS_SUCCESS(reused.status, "16-bit: 40 decodes as INC AX");
        CHECK(reused.instruction.mnemonic == ZYDIS_MNEMONIC_INC, "16-bit: mnemonic is INC");
        CHECK(reused.instruction.operand_width == 16, "16-bit: operand width is 16");
        CHECK(reused.operands[0].reg.value == ZYDIS_REGISTER_AX, "16-bit: operand is AX");

        {
            ZydisDecoder fresh;
            CHECK_STATUS_SUCCESS(ZydisDecoderInit(&fresh, ZYDIS_MACHINE_MODE_LEGACY_16,
                ZYDIS_STACK_WIDTH_16), "init fresh 16-bit decoder");
            DecodeFull(&fresh, inc_ax, sizeof(inc_ax), &pristine);
        }
        CHECK(ResultsEqual(&reused, &pristine),
            "16-bit result after 64-bit REX decode equals fresh decoder result");
    }
}

/* ============================================================================================== */
/* Entry point                                                                                    */
/* ============================================================================================== */

int main(void)
{
    TestMachineModeSwitching();
    TestAddressWidthSwitching();
    TestDecoderModeToggling();
    TestIllegalPrefixesAndTruncation();
    TestFailureCleanup();
    TestCrossModeStateIsolation();

    printf("\n%d checks, %d failures\n", g_checks, g_failures);
    return g_failures ? 1 : 0;
}
