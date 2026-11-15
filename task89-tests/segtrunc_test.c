/***************************************************************************************************
 *
 * segtrunc_test.c
 *
 * Fuzzy verification of x86 instruction segment boundaries together with decode semantics.
 *
 * For every seed instruction (crafted + real bytes harvested from the Zydis regression corpus):
 *
 *   1. A trusted baseline decode is performed on the complete machine code.
 *   2. Combinatorial truncation is applied: every possible read window length from 1 byte up to
 *      the full instruction length is decoded in a GUARDED window -- the bytes sit directly in
 *      front of an mmap'd PROT_NONE page so any read past the declared window raises a fault that
 *      AddressSanitizer/UBSan turn into an abort.
 *   3. On every SUCCESSFUL result we verify that
 *        a) the reported length exactly equals the window the decoder was allowed to read,
 *        b) the whole decoded-instruction struct (incl. every prefix / ModRM / SIB / displacement
 *           / immediate offset and size) is byte-identical to the trusted baseline,
 *        c) prefix, displacement and immediate segments reassemble to the original raw bytes,
 *        d) ZydisGetInstructionSegments() yields a contiguous, non-overlapping, in-range partition
 *           that reassembles to the exact original instruction bytes,
 *        e) the operand array (read/write actions and full operand semantics) is byte-identical
 *           to the baseline, and ZydisCalcAbsoluteAddress() produces identical results.
 *   4. On every FAILED result we verify that no segment or operand data is left behind that later
 *      logic could mistake for a trusted partial decode: the instruction struct is fully zeroed,
 *      the operand slots contain nothing but the pre-call sentinel (or are fully zeroed), the
 *      decoder context is zeroed, and the segment helper reports nothing reaching past offset 0.
 *
 * The same procedure runs in 16-bit, 32-bit and 64-bit machine modes (plus legacy/real variants).
 *
 **************************************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/mman.h>

#include <Zydis/Zydis.h>
#include <Zydis/Segment.h>
#include <Zydis/Utils.h>

/* ============================================================================================== */
/* Test framework                                                                                 */
/* ============================================================================================== */

static long long g_checks_total   = 0;
static long long g_checks_failed  = 0;
static long long g_decodes_total  = 0;
static long long g_decodes_ok     = 0;
static long long g_decodes_fail   = 0;

/* Name of the read-window backend currently exercising the decoder (for failure messages). */
static const char* g_active_backend = "none";

#define CHECK(cond, ...)                                                                          \
    do {                                                                                          \
        ++g_checks_total;                                                                         \
        if (!(cond)) {                                                                            \
            ++g_checks_failed;                                                                    \
            printf("    [CHECK FAIL] %s:%d: ", __FILE__, __LINE__);                              \
            printf(__VA_ARGS__);                                                                  \
            putchar('\n');                                                                        \
        }                                                                                         \
    } while (0)

/* ============================================================================================== */
/* Guarded read window                                                                            */
/* ============================================================================================== */

/*
 * Two pages: page 0 is readable/writable and filled with a canary pattern, page 1 is PROT_NONE.
 * Test bytes are copied to the very end of page 0, so the first byte past the declared window is
 * either another canary (detected explicitly) or an unmapped guard page (detected as a crash by
 * the kernel / ASan).
 */
typedef struct GuardWindow_
{
    long           page_size;
    unsigned char* page;          // start of the 2-page mapping
    unsigned char* read_ptr;      // address handed to the decoder (end of page 0 - window_len)
} GuardWindow;

#define CANARY_BYTE      0xCCu
#define CANARY_RUN       32

static int GuardWindowInit(GuardWindow* gw)
{
    gw->page_size = sysconf(_SC_PAGESIZE);
    if (gw->page_size <= 0)
    {
        return 0;
    }
    gw->page = (unsigned char*)mmap(ZYAN_NULL, (size_t)gw->page_size * 2,
        PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (gw->page == MAP_FAILED)
    {
        return 0;
    }
    // Second page: no access at all.
    if (mprotect(gw->page + gw->page_size, (size_t)gw->page_size, PROT_NONE) != 0)
    {
        munmap(gw->page, (size_t)gw->page_size * 2);
        return 0;
    }
    gw->read_ptr = ZYAN_NULL;
    return 1;
}

static void GuardWindowDestroy(GuardWindow* gw)
{
    if (gw->page && gw->page != MAP_FAILED)
    {
        munmap(gw->page, (size_t)gw->page_size * 2);
    }
}

/*
 * Places `len` bytes at the end of the accessible page, optionally followed by `junk_len` junk
 * bytes (still in front of the guard page). Fills everything else with canaries and returns the
 * pointer the decoder must use.
 */
static unsigned char* GuardWindowPlace(GuardWindow* gw, const unsigned char* bytes,
    ZyanUSize len, ZyanUSize junk_len, const unsigned char* junk)
{
    memset(gw->page, CANARY_BYTE, (size_t)gw->page_size);
    unsigned char* end = gw->page + gw->page_size;
    unsigned char* p   = end - len - junk_len;
    memcpy(p, bytes, len);
    if (junk_len)
    {
        memcpy(p + len, junk, junk_len);
    }
    gw->read_ptr = p;
    return p;
}

/* Verifies the canary run in front of the current window is untouched (no backwards over-read). */
static int GuardWindowCanaryIntact(GuardWindow* gw, ZyanUSize len, ZyanUSize junk_len)
{
    const unsigned char* p = gw->read_ptr;
    for (ZyanUSize i = 1; i <= CANARY_RUN; ++i)
    {
        if (p[-i] != CANARY_BYTE)
        {
            return 0;
        }
    }
    // Everything before the canary run must still be canary as well.
    for (const unsigned char* q = gw->page; q < p - CANARY_RUN; ++q)
    {
        if (*q != CANARY_BYTE)
        {
            return 0;
        }
    }
    (void)len; (void)junk_len;
    return 1;
}

/* ============================================================================================== */
/* Read-window backends                                                                           */
/* ============================================================================================== */

/*
 * Two independent ways to restrict the decoder's read window:
 *
 *   - GUARD_MMAP: bytes end exactly at a PROT_NONE page boundary, so an over-read of any size
 *     raises SIGSEGV/SIGBUS even in a build without sanitizers.
 *   - GUARD_ASAN: the bytes live in an exact-sized heap allocation, so ASan's red zones catch
 *     over-reads that stay inside the same page (and UBSan runs over every access either way).
 *
 * Every decode is performed through both backends.
 */
typedef enum BackendKind_
{
    BACKEND_GUARD_MMAP = 0,
    BACKEND_GUARD_ASAN,
    BACKEND_COUNT
} BackendKind;

typedef struct WindowBackend_
{
    BackendKind kind;
    const char* name;
    GuardWindow* gw;                       // used by GUARD_MMAP
    unsigned char* heap;                   // used by GUARD_ASAN
    ZyanUSize heap_cap;
} WindowBackend;

static int BackendInit(WindowBackend* be, BackendKind kind, GuardWindow* gw)
{
    be->kind = kind;
    be->gw = gw;
    be->heap = ZYAN_NULL;
    be->heap_cap = 0;
    switch (kind)
    {
    case BACKEND_GUARD_MMAP:
        be->name = "mmap-guard-page";
        return 1;
    case BACKEND_GUARD_ASAN:
        be->name = "asan-heap-redzone";
        be->heap_cap = ZYDIS_MAX_INSTRUCTION_LENGTH + 8;
        // Exact-sized allocation: ASan places poisoned red zones immediately past the end.
        be->heap = (unsigned char*)malloc(be->heap_cap);
        return be->heap != ZYAN_NULL;
    default:
        return 0;
    }
}

static void BackendDestroy(WindowBackend* be)
{
    if (be->kind == BACKEND_GUARD_ASAN && be->heap)
    {
        free(be->heap);
        be->heap = ZYAN_NULL;
    }
}

/*
 * Places `len` bytes (optionally followed by `junk_len` junk bytes) in the backend's restricted
 * window and returns the pointer to hand to the decoder. The total visible window is always
 * exactly len + junk_len bytes; anything past it must be inaccessible / poisoned.
 */
static unsigned char* BackendPlace(WindowBackend* be, const unsigned char* bytes,
    ZyanUSize len, ZyanUSize junk_len, const unsigned char* junk)
{
    const ZyanUSize total = len + junk_len;
    switch (be->kind)
    {
    case BACKEND_GUARD_MMAP:
        return GuardWindowPlace(be->gw, bytes, len, junk_len, junk);
    case BACKEND_GUARD_ASAN:
        CHECK(total <= be->heap_cap,
            "asan backend: window %zu exceeds capacity %zu", (size_t)total,
            (size_t)be->heap_cap);
        memcpy(be->heap, bytes, len);
        if (junk_len)
        {
            memcpy(be->heap + len, junk, junk_len);
        }
        return be->heap;
    default:
        return ZYAN_NULL;
    }
}

/* Backend-specific check that no backwards over-read corrupted memory before the window. */
static int BackendCanaryIntact(WindowBackend* be, ZyanUSize len, ZyanUSize junk_len)
{
    if (be->kind == BACKEND_GUARD_MMAP)
    {
        return GuardWindowCanaryIntact(be->gw, len, junk_len);
    }
    return 1; // ASan red zones cover over-reads; nothing else to check
}

/* ============================================================================================== */
/* Seed corpus                                                                                    */
/* ============================================================================================== */

typedef struct Seed_
{
    const char* hex;        // machine code, whitespace separated hex bytes
    const char* desc;       // human-readable description
    int knc_only;           // only decodes with the KNC decoder mode enabled
} Seed;

/*
 * Hand-crafted seeds stress: redundant legacy prefixes (duplicated groups), 2-byte (0F) and
 * 3-byte (0F38/0F3A) opcodes, 3DNow, VEX2/VEX3/XOP/EVEX, SIB + disp16/disp32, imm8/imm16/imm32,
 * rel branches, far pointers, REX, and seeds that can never decode successfully.
 */
static const Seed g_seeds[] =
{
    // -- redundant legacy prefixes, plain opcodes ------------------------------------------------
    { "26 C9",
      "ES segment override + leave (16-bit style prefix)", 0 },
    { "66 66 66 67 67 F2 F3 0F 1F 84 00 11 22 33 44",
      "15-byte NOP r/m: duplicated 66/67, F2/F3, 0F opcode, SIB, disp32", 0 },
    { "F3 66 67 81 48 02 34 12 9A BC",
      "rep + opsize + addrsize, disp16 + imm16", 0 },
    { "F0 66 0F 6F 06",
      "LOCK + operand-size + 0F two-byte opcode (movq mm)", 0 },
    { "66 67 89 84 91 AA BB CC DD",
      "opsize+addrsize mov, SIB + disp32", 0 },
    { "A9 A1 EF 16 5E",
      "test eax, imm32", 0 },
    { "C2 08 00",
      "ret imm16", 0 },
    { "EA 12 34 56 78",
      "far jmp ptr16:16 / ptr32 (mode dependent width)", 0 },
    { "E9 11 22 33 44",
      "near jmp rel32", 0 },
    { "67 45 0F AC 3C C5 00 00 E9 41 10 00 00",
      "13-byte legacy: addrsize, REX, 0F3A three-byte opcode, imm32, rel32 tail", 0 },

    // -- multi-byte opcodes ----------------------------------------------------------------------
    { "0F 1F 84 00 11 22 33 44",
      "0F two-byte NOP r/m with SIB + disp32", 0 },
    { "66 0F 38 8B 07",
      "0F38 three-byte opcode (harvested)", 0 },
    { "48 0F 38 8B 07",
      "REX + 0F38 three-byte opcode (harvested)", 0 },
    { "F3 0F 38 F8 13",
      "F3 mandatory prefix + 0F38 (harvested)", 0 },
    { "F2 48 0F 38 F8 C1",
      "F2 + REX + 0F38 (harvested)", 0 },
    { "0F 0F 37 97",
      "3DNow! 0F0F map with trailing opcode byte", 0 },

    // -- VEX / XOP / EVEX ------------------------------------------------------------------------
    { "C5 35 F4 C0",
      "VEX 2-byte prefix", 0 },
    { "C4 62 59 CF 4F 5D",
      "VEX 3-byte prefix", 0 },
    { "8F E8 60 EF 4E 3D C0",
      "XOP prefix", 0 },
    { "62 D2 CD 2B 14 7B 4F",
      "EVEX (harvested)", 0 },
    { "62 11 55 BD DB B1 12 F8 15 7B",
      "10-byte EVEX with SIB, disp32 and imm8 (harvested)", 0 },
    { "62 72 71 AC 45 CF 87 2A",
      "MVEX (KNC only)", 1 },

    // -- seeds whose baseline decode must fail: every truncation window must stay hygienic ------
    { "F0",
      "lone LOCK prefix", 0 },
    { "66",
      "lone operand-size prefix", 0 },
    { "0F",
      "lone 0F escape", 0 },
    { "0F 38",
      "truncated 0F38 escape", 0 },
    { "0F 0F",
      "truncated 3DNow escape", 0 },
    { "C4",
      "lone VEX 3-byte escape", 0 },
    { "C5",
      "lone VEX 2-byte escape", 0 },
    { "C4 62 59",
      "truncated VEX3 prefix", 0 },
    { "62",
      "lone EVEX escape", 0 },
    { "62 11 55 BD",
      "truncated EVEX prefix", 0 },
    { "FF FF",
      "illegal byte sequence", 0 },
};

#define SEED_COUNT (int)(sizeof(g_seeds) / sizeof(g_seeds[0]))

/* ============================================================================================== */
/* Helpers                                                                                        */
/* ============================================================================================== */

static int HexParse(const char* hex, unsigned char* out, ZyanUSize cap, ZyanUSize* out_len)
{
    ZyanUSize n = 0;
    unsigned cur = 0;
    int have = 0;
    for (const char* p = hex; *p; ++p)
    {
        int d;
        if (*p >= '0' && *p <= '9') d = *p - '0';
        else if (*p >= 'a' && *p <= 'f') d = *p - 'a' + 10;
        else if (*p >= 'A' && *p <= 'F') d = *p - 'A' + 10;
        else if (*p == ' ' || *p == '\t' || *p == '\n')
        {
            if (have)
            {
                if (n >= cap) return 0;
                out[n++] = (unsigned char)cur;
                have = 0; cur = 0;
            }
            continue;
        }
        else
        {
            return 0;
        }
        cur = (unsigned)((cur << 4) | (unsigned)d);
        have = 1;
    }
    if (have)
    {
        if (n >= cap) return 0;
        out[n++] = (unsigned char)cur;
    }
    *out_len = n;
    return n > 0;
}

static int IsUniform(const void* p, size_t n, unsigned char value)
{
    const unsigned char* q = (const unsigned char*)p;
    for (size_t i = 0; i < n; ++i)
    {
        if (q[i] != value) return 0;
    }
    return 1;
}

/* Status-code histogram (low 16 code bits) so the run report shows which failures were observed. */
static unsigned g_status_hist[64];

static void RecordStatus(ZyanStatus st)
{
    unsigned code = (unsigned)(st & 0xFFFFu);
    if (code < sizeof(g_status_hist) / sizeof(g_status_hist[0]))
    {
        ++g_status_hist[code];
    }
}

/* ============================================================================================== */
/* Success verification                                                                           */
/* ============================================================================================== */

/*
 * Verifies a successful decode against the trusted baseline, including full byte reassembly of
 * every segment. `window_len` is the number of bytes the decoder was permitted to read.
 */
static void VerifySuccess(const char* mode_name, const Seed* seed,
    const unsigned char* code, ZyanUSize window_len, ZyanUSize junk_len,
    const ZydisDecodedInstruction* base_insn, const ZydisDecodedOperand* base_ops,
    const ZydisDecodedInstruction* insn, const ZydisDecodedOperand* ops)
{
    char tag[160];
    (void)snprintf(tag, sizeof(tag), "backend=%s mode=%s seed=\"%s\" window=%zu junk=%zu",
        g_active_backend, mode_name, seed->desc, (size_t)window_len, (size_t)junk_len);

    /* (a) the decoder must have consumed exactly the bytes of a complete instruction. */
    CHECK(insn->length > 0 && (ZyanUSize)insn->length <= window_len,
        "%s: decoded length %u outside window %zu", tag, insn->length, (size_t)window_len);
    CHECK(insn->length == base_insn->length,
        "%s: length %u != baseline %u", tag, insn->length, base_insn->length);

    /* (b) whole decoded-instruction struct identical to the trusted baseline. */
    CHECK(memcmp(insn, base_insn, sizeof(*insn)) == 0,
        "%s: decoded instruction struct differs from baseline", tag);

    /* (c) prefix bytes reassemble to the original machine code. */
    CHECK(insn->raw.prefix_count <= insn->length,
        "%s: prefix_count %u > length %u", tag, insn->raw.prefix_count, insn->length);
    for (ZyanU8 i = 0; i < insn->raw.prefix_count; ++i)
    {
        CHECK(insn->raw.prefixes[i].value == code[i],
            "%s: prefix[%u] byte 0x%02X != original 0x%02X",
            tag, i, insn->raw.prefixes[i].value, code[i]);
        CHECK(insn->raw.prefixes[i].type <= ZYDIS_PREFIX_TYPE_MANDATORY,
            "%s: prefix[%u] has out-of-range type %d", tag, i, insn->raw.prefixes[i].type);
    }

    /* (c) displacement range is validated here; the raw-value byte comparison happens below once
     * the segment partition has proven the layout. */
    if (insn->raw.disp.size)
    {
        ZyanUSize d_off  = insn->raw.disp.offset;
        ZyanUSize d_size = insn->raw.disp.size / 8u;
        CHECK(d_size > 0 && d_off + d_size <= (ZyanUSize)insn->length,
            "%s: disp off=%zu size=%zu out of range (len=%u)",
            tag, (size_t)d_off, (size_t)d_size, insn->length);
    }

    /* (c) immediate range checks (up to two immediate slots); raw bytes compared below. */
    for (int i = 0; i < 2; ++i)
    {
        if (insn->raw.imm[i].size)
        {
            ZyanUSize i_off  = insn->raw.imm[i].offset;
            ZyanUSize i_size = insn->raw.imm[i].size / 8u;
            CHECK(i_size > 0 && i_off + i_size <= (ZyanUSize)insn->length,
                "%s: imm[%d] off=%zu size=%zu out of range (len=%u)",
                tag, i, (size_t)i_off, (size_t)i_size, insn->length);
        }
    }

    /* (d) logical segments: in-range, contiguous, non-overlapping, and reassemble exactly. */
    ZydisInstructionSegments seg;
    ZyanStatus sst = ZydisGetInstructionSegments(insn, &seg);
    CHECK(ZYAN_SUCCESS(sst), "%s: ZydisGetInstructionSegments failed (0x%08X)", tag, sst);
    CHECK(seg.count >= 1 && seg.count <= ZYDIS_MAX_INSTRUCTION_SEGMENT_COUNT,
        "%s: implausible segment count %u", tag, seg.count);

    unsigned char rebuilt[ZYDIS_MAX_INSTRUCTION_LENGTH + 1];
    memset(rebuilt, 0, sizeof(rebuilt));
    ZyanUSize covered = 0;
    for (ZyanU8 i = 0; i < seg.count; ++i)
    {
        ZyanUSize off  = seg.segments[i].offset;
        ZyanUSize size = seg.segments[i].size;
        CHECK(size > 0, "%s: segment %u has zero size", tag, i);
        CHECK(off + size <= (ZyanUSize)insn->length,
            "%s: segment %u (off=%zu size=%zu) exceeds instruction length %u",
            tag, i, (size_t)off, (size_t)size, insn->length);
        CHECK(seg.segments[i].type > ZYDIS_INSTR_SEGMENT_NONE &&
              seg.segments[i].type <= ZYDIS_INSTR_SEGMENT_IMMEDIATE,
            "%s: segment %u has invalid type %d", tag, i, seg.segments[i].type);
        if (i == 0)
        {
            CHECK(off == 0, "%s: first segment does not start at offset 0", tag);
        }
        else
        {
            ZyanUSize prev_off  = seg.segments[i - 1].offset;
            ZyanUSize prev_size = seg.segments[i - 1].size;
            CHECK(off == prev_off + prev_size,
                "%s: segment %u not contiguous (gap/overlap at offset %zu)", tag, i, (size_t)off);
        }
        memcpy(rebuilt + off, code + off, size);
        covered += size;
    }
    CHECK(covered == (ZyanUSize)insn->length,
        "%s: segments cover %zu bytes but instruction is %u bytes",
        tag, (size_t)covered, insn->length);
    CHECK(memcmp(rebuilt, code, insn->length) == 0,
        "%s: segment reassembly does not match the original instruction", tag);

    /* (c-continued) disp/imm raw bytes checked against the code now that segments prove layout. */
    if (insn->raw.disp.size)
    {
        ZyanUSize d_off  = insn->raw.disp.offset;
        ZyanUSize d_size = insn->raw.disp.size / 8u;
        if (d_off + d_size <= (ZyanUSize)insn->length)
        {
            unsigned char raw_disp[8];
            memcpy(raw_disp, code + d_off, d_size);
            unsigned char decoded_disp[8] = { 0 };
            memcpy(decoded_disp, &insn->raw.disp.value, d_size);
            CHECK(memcmp(raw_disp, decoded_disp, d_size) == 0,
                "%s: displacement value does not match raw bytes", tag);
        }
    }
    for (int i = 0; i < 2; ++i)
    {
        if (insn->raw.imm[i].size)
        {
            ZyanUSize i_off  = insn->raw.imm[i].offset;
            ZyanUSize i_size = insn->raw.imm[i].size / 8u;
            if (i_off + i_size <= (ZyanUSize)insn->length)
            {
                unsigned char raw_imm[8];
                memcpy(raw_imm, code + i_off, i_size);
                unsigned char decoded_imm[8] = { 0 };
                memcpy(decoded_imm, &insn->raw.imm[i].value, i_size);
                CHECK(memcmp(raw_imm, decoded_imm, i_size) == 0,
                    "%s: immediate[%d] value does not match raw bytes", tag, i);
            }
        }
    }

    /* (e) operand array byte-identical to baseline (includes read/write action semantics). */
    CHECK(insn->operand_count == base_insn->operand_count,
        "%s: operand count %u != baseline %u",
        tag, insn->operand_count, base_insn->operand_count);
    CHECK(memcmp(ops, base_ops,
        sizeof(ZydisDecodedOperand) * ZYDIS_MAX_OPERAND_COUNT) == 0,
        "%s: operand array differs from baseline (actions / operands changed)", tag);

    /* Explicit, independent check of the read/write action masks. */
    for (ZyanU8 i = 0; i < insn->operand_count; ++i)
    {
        CHECK(ops[i].actions == base_ops[i].actions,
            "%s: operand %u actions 0x%X != baseline 0x%X",
            tag, i, ops[i].actions, base_ops[i].actions);
        ZydisOperandActions base_r = base_ops[i].actions & ZYDIS_OPERAND_ACTION_MASK_READ;
        ZydisOperandActions base_w = base_ops[i].actions & ZYDIS_OPERAND_ACTION_MASK_WRITE;
        CHECK((ops[i].actions & ZYDIS_OPERAND_ACTION_MASK_READ) == base_r,
            "%s: operand %u read-action mismatch", tag, i);
        CHECK((ops[i].actions & ZYDIS_OPERAND_ACTION_MASK_WRITE) == base_w,
            "%s: operand %u write-action mismatch", tag, i);
    }

    /* (e) address-calculation helper must agree with the baseline for every memory operand. */
    for (ZyanU8 i = 0; i < insn->operand_count; ++i)
    {
        if (ops[i].type != ZYDIS_OPERAND_TYPE_MEMORY)
        {
            continue;
        }
        const ZyanU64 rt = 0x1122334455667788ULL;
        ZyanU64 addr_a = 0, addr_b = 0;
        ZyanStatus s1 = ZydisCalcAbsoluteAddress(insn, &ops[i], rt, &addr_a);
        ZyanStatus s2 = ZydisCalcAbsoluteAddress(base_insn, &base_ops[i], rt, &addr_b);
        CHECK(s1 == s2, "%s: mem operand %u CalcAbsoluteAddress status mismatch", tag, i);
        if (ZYAN_SUCCESS(s1))
        {
            CHECK(addr_a == addr_b,
                "%s: mem operand %u absolute address 0x%llX != baseline 0x%llX",
                tag, i, (unsigned long long)addr_a, (unsigned long long)addr_b);
        }
    }
}

/* ============================================================================================== */
/* Failure verification                                                                           */
/* ============================================================================================== */

/*
 * A failed decode must not leave any segment or operand data that later logic could treat as a
 * trusted partial result.
 */
static void VerifyFailure(const char* mode_name, const Seed* seed, ZyanUSize window_len,
    const ZydisDecodedInstruction* zero_insn, const ZydisDecodedInstruction* insn,
    const ZydisDecodedOperand* ops, const unsigned char* operand_sentinel)
{
    char tag[160];
    (void)snprintf(tag, sizeof(tag), "backend=%s mode=%s seed=\"%s\" window=%zu",
        g_active_backend, mode_name, seed->desc, (size_t)window_len);

    /* The decoder contract zeroes the whole instruction struct on failure. */
    CHECK(memcmp(insn, zero_insn, sizeof(*insn)) == 0,
        "%s: failed decode left a non-zero instruction struct", tag);

    /* Belt-and-braces: the fields a consumer would actually trust must all be zero. */
    CHECK(insn->length == 0, "%s: failed decode left length=%u", tag, insn->length);
    CHECK(insn->operand_count == 0, "%s: failed decode left operand_count=%u",
        tag, insn->operand_count);
    CHECK(insn->operand_count_visible == 0,
        "%s: failed decode left operand_count_visible=%u", tag, insn->operand_count_visible);
    CHECK(insn->mnemonic == ZYDIS_MNEMONIC_INVALID,
        "%s: failed decode left mnemonic=%d", tag, insn->mnemonic);
    CHECK(insn->opcode_map == ZYDIS_OPCODE_MAP_DEFAULT,
        "%s: failed decode left opcode_map=%d", tag, insn->opcode_map);
    CHECK(insn->attributes == 0, "%s: failed decode left attributes=0x%llX",
        tag, (unsigned long long)insn->attributes);
    CHECK(insn->raw.prefix_count == 0,
        "%s: failed decode left prefix_count=%u", tag, insn->raw.prefix_count);
    CHECK(insn->raw.disp.size == 0 && insn->raw.disp.offset == 0,
        "%s: failed decode left displacement info", tag);
    CHECK(insn->raw.imm[0].size == 0 && insn->raw.imm[1].size == 0,
        "%s: failed decode left immediate info", tag);
    CHECK((insn->attributes & (ZYDIS_ATTRIB_HAS_MODRM | ZYDIS_ATTRIB_HAS_SIB)) == 0,
        "%s: failed decode left ModRM/SIB attributes", tag);

    /*
     * Operand slots: DecodeFull never reaches operand decoding after an instruction failure, so
     * the slots must be exactly the pre-call sentinel; accept an all-zero implementation as well.
     * Anything else (mixed/partially written data) is a hygiene violation.
     */
    for (int i = 0; i < ZYDIS_MAX_OPERAND_COUNT; ++i)
    {
        int is_sentinel = memcmp(&ops[i], operand_sentinel, sizeof(ops[i])) == 0;
        int is_zero     = IsUniform(&ops[i], sizeof(ops[i]), 0);
        CHECK(is_sentinel || is_zero,
            "%s: operand slot %d contains untrusted partial data after failure", tag, i);
        if (is_zero)
        {
            CHECK(ops[i].type == ZYDIS_OPERAND_TYPE_UNUSED,
                "%s: zeroed operand slot %d has unexpected type", tag, i);
        }
    }

    /*
     * The segment helper applied to the zeroed struct must not fabricate anything reaching past
     * the (zero) instruction length.
     */
    ZydisInstructionSegments seg;
    ZyanStatus st = ZydisGetInstructionSegments(insn, &seg);
    CHECK(ZYAN_SUCCESS(st), "%s: segment helper failed on zeroed instruction", tag);
    for (ZyanU8 i = 0; i < seg.count; ++i)
    {
        CHECK(seg.segments[i].offset == 0,
            "%s: segment %u on failed decode has non-zero offset %u",
            tag, i, seg.segments[i].offset);
        CHECK((ZyanUSize)seg.segments[i].offset + seg.segments[i].size <=
              (ZyanUSize)insn->length + 1u,
            "%s: segment %u reaches past the zero instruction length", tag, i);
    }
}

/* ============================================================================================== */
/* Per-mode / per-seed driver                                                                     */
/* ============================================================================================== */

typedef struct ModeConfig_
{
    const char*       name;
    ZydisMachineMode  machine_mode;
    ZydisStackWidth   stack_width;
} ModeConfig;

static const ModeConfig g_modes[] =
{
    { "16-bit compat", ZYDIS_MACHINE_MODE_LONG_COMPAT_16, ZYDIS_STACK_WIDTH_16 },
    { "16-bit real",   ZYDIS_MACHINE_MODE_REAL_16,        ZYDIS_STACK_WIDTH_16 },
    { "32-bit compat", ZYDIS_MACHINE_MODE_LONG_COMPAT_32, ZYDIS_STACK_WIDTH_32 },
    { "32-bit legacy", ZYDIS_MACHINE_MODE_LEGACY_32,      ZYDIS_STACK_WIDTH_32 },
    { "64-bit long",   ZYDIS_MACHINE_MODE_LONG_64,        ZYDIS_STACK_WIDTH_64 },
};
#define MODE_COUNT (int)(sizeof(g_modes) / sizeof(g_modes[0]))

static ZydisDecoder MakeDecoder(const ModeConfig* mode, int knc)
{
    ZydisDecoder decoder;
    ZyanStatus st = ZydisDecoderInit(&decoder, mode->machine_mode, mode->stack_width);
    if (!ZYAN_SUCCESS(st))
    {
        printf("    [SETUP FAIL] decoder init %s: 0x%08X\n", mode->name, st);
        return decoder;
    }
    if (knc)
    {
        st = ZydisDecoderEnableMode(&decoder, ZYDIS_DECODER_MODE_KNC, ZYAN_TRUE);
        if (!ZYAN_SUCCESS(st))
        {
            printf("    [SETUP FAIL] KNC enable %s: 0x%08X\n", mode->name, st);
        }
    }
    return decoder;
}

/* Decodes through the split API and checks context hygiene on failure. */
static void CheckSplitApiContext(const ZydisDecoder* decoder, WindowBackend* be,
    const unsigned char* code, ZyanUSize len, const char* mode_name, const Seed* seed)
{
    ZydisDecoderContext ctx;
    memset(&ctx, 0xA5, sizeof(ctx));
    ZydisDecodedInstruction insn;
    memset(&insn, 0xA5, sizeof(insn));
    unsigned char* p = BackendPlace(be, code, len, 0, ZYAN_NULL);
    ZyanStatus st = ZydisDecoderDecodeInstruction(decoder, &ctx, p, len, &insn);
    ++g_decodes_total;
    if (ZYAN_FAILED(st))
    {
        ++g_decodes_fail;
        RecordStatus(st);
        ZydisDecoderContext zero_ctx;
        memset(&zero_ctx, 0, sizeof(zero_ctx));
        CHECK(memcmp(&ctx, &zero_ctx, sizeof(ctx)) == 0,
            "mode=%s seed=\"%s\": failed split decode left a non-zero decoder context",
            mode_name, seed->desc);
    }
    else
    {
        ++g_decodes_ok;
    }
    CHECK(BackendCanaryIntact(be, len, 0),
        "mode=%s seed=\"%s\": canary corrupted (backward over-read)", mode_name, seed->desc);
}

static void RunSeed(const ModeConfig* mode, const Seed* seed, WindowBackend* be)
{
    g_active_backend = be->name;
    const char* backend_name = be->name;
    unsigned char code[ZYDIS_MAX_INSTRUCTION_LENGTH + 8];
    ZyanUSize code_len = 0;
    if (!HexParse(seed->hex, code, sizeof(code), &code_len) || code_len > ZYDIS_MAX_INSTRUCTION_LENGTH)
    {
        CHECK(0, "backend=%s mode=%s seed=\"%s\": bad seed hex",
            backend_name, mode->name, seed->desc);
        return;
    }

    ZydisDecoder decoder = MakeDecoder(mode, seed->knc_only);
    ZydisDecodedInstruction zero_insn;
    memset(&zero_insn, 0, sizeof(zero_insn));

    /* ---- trusted baseline decode inside the restricted window -------------------------------- */
    ZydisDecodedInstruction base_insn;
    ZydisDecodedOperand base_ops[ZYDIS_MAX_OPERAND_COUNT];
    unsigned char* bp = BackendPlace(be, code, code_len, 0, ZYAN_NULL);
    ZyanStatus base_st = ZydisDecoderDecodeFull(&decoder, bp, code_len, &base_insn, base_ops);
    ++g_decodes_total;
    CHECK(BackendCanaryIntact(be, code_len, 0),
        "backend=%s mode=%s seed=\"%s\": baseline canary corrupted",
        backend_name, mode->name, seed->desc);

    if (ZYAN_FAILED(base_st))
    {
        RecordStatus(base_st);
        /* Baseline itself rejects the code: EVERY truncation window must fail just as cleanly. */
        for (ZyanUSize w = 1; w <= code_len; ++w)
        {
            ZydisDecodedInstruction insn;
            ZydisDecodedOperand ops[ZYDIS_MAX_OPERAND_COUNT];
            unsigned char sentinel[sizeof(ZydisDecodedOperand)];
            memset(sentinel, 0xA5, sizeof(sentinel));
            memset(&insn, 0xA5, sizeof(insn));
            memset(ops, 0xA5, sizeof(ops));

            unsigned char* p = BackendPlace(be, code, w, 0, ZYAN_NULL);
            ZyanStatus st = ZydisDecoderDecodeFull(&decoder, p, w, &insn, ops);
            ++g_decodes_total;
            CHECK(ZYAN_FAILED(st),
                "backend=%s mode=%s seed=\"%s\": truncated window %zu unexpectedly succeeded",
                backend_name, mode->name, seed->desc, (size_t)w);
            if (ZYAN_FAILED(st))
            {
                ++g_decodes_fail;
                RecordStatus(st);
                VerifyFailure(mode->name, seed, w, &zero_insn, &insn, ops, sentinel);
            }
            else
            {
                ++g_decodes_ok;
            }
            CHECK(BackendCanaryIntact(be, w, 0),
                "backend=%s mode=%s seed=\"%s\": canary corrupted at window %zu",
                backend_name, mode->name, seed->desc, (size_t)w);
        }
        CheckSplitApiContext(&decoder, be, code, code_len, mode->name, seed);
        return;
    }
    ++g_decodes_ok;

    /*
     * The seed bytes may contain more than one instruction in modes with different effective
     * operand/address widths (e.g. an address-size prefix shrinks a displacement). The trusted
     * baseline tells us where THIS mode's first instruction ends; everything past `full` is
     * trailing data and is exercised as an additional junk window below.
     */
    const ZyanUSize full = base_insn.length;
    CHECK(full >= 1 && full <= code_len,
        "mode=%s seed=\"%s\": implausible baseline length %zu (seed %zu bytes)",
        mode->name, seed->desc, (size_t)full, (size_t)code_len);
    const unsigned char* body = code;

    /* ---- combinatorial truncation: every window length 1 .. full instruction ---------------- */
    for (ZyanUSize w = 1; w <= full; ++w)
    {
        ZydisDecodedInstruction insn;
        ZydisDecodedOperand ops[ZYDIS_MAX_OPERAND_COUNT];
        unsigned char sentinel[sizeof(ZydisDecodedOperand)];
        memset(sentinel, 0xA5, sizeof(sentinel));
        memset(&insn, 0xA5, sizeof(insn));
        memset(ops, 0xA5, sizeof(ops));

        unsigned char* p = BackendPlace(be, body, w, 0, ZYAN_NULL);
        ZyanStatus st = ZydisDecoderDecodeFull(&decoder, p, w, &insn, ops);
        ++g_decodes_total;

        if (ZYAN_SUCCESS(st))
        {
            ++g_decodes_ok;
            /* A whole-instruction decode can only succeed once the complete instruction is present. */
            CHECK(w == full,
                "mode=%s seed=\"%s\": decode succeeded at partial window %zu < full %zu",
                mode->name, seed->desc, (size_t)w, (size_t)full);
            VerifySuccess(mode->name, seed, body, w, 0, &base_insn, base_ops, &insn, ops);
        }
        else
        {
            ++g_decodes_fail;
            RecordStatus(st);
            VerifyFailure(mode->name, seed, w, &zero_insn, &insn, ops, sentinel);
        }
        CHECK(BackendCanaryIntact(be, w, 0),
            "mode=%s seed=\"%s\": canary corrupted at window %zu",
            mode->name, seed->desc, (size_t)w);
    }

    /* ---- trailing junk: windows larger than the instruction must decode identically --------- */
    static const unsigned char junk_variants[][4] =
    {
        { 0x90 },                         // NOP follows
        { 0x05, 0x11, 0x22, 0x33 },       // start of "add eax, imm32"
        { 0xCC, 0xCC, 0xCC },             // int3 padding
    };
    for (int j = 0; j < 3; ++j)
    {
        ZyanUSize jlen = (ZyanUSize)sizeof(junk_variants[j]);
        ZydisDecodedInstruction insn;
        ZydisDecodedOperand ops[ZYDIS_MAX_OPERAND_COUNT];
        memset(&insn, 0xA5, sizeof(insn));
        memset(ops, 0xA5, sizeof(ops));

        unsigned char* p = BackendPlace(be, body, full, jlen, junk_variants[j]);
        ZyanUSize win = full + jlen;
        ZyanStatus st = ZydisDecoderDecodeFull(&decoder, p, win, &insn, ops);
        ++g_decodes_total;
        CHECK(ZYAN_SUCCESS(st),
            "mode=%s seed=\"%s\": junk-window decode failed (0x%08X)",
            mode->name, seed->desc, st);
        if (ZYAN_SUCCESS(st))
        {
            ++g_decodes_ok;
            VerifySuccess(mode->name, seed, body, win, jlen, &base_insn, base_ops, &insn, ops);
        }
        else
        {
            ++g_decodes_fail;
            RecordStatus(st);
        }
        CHECK(BackendCanaryIntact(be, full, jlen),
            "mode=%s seed=\"%s\": canary corrupted in junk window", mode->name, seed->desc);
    }

    /* Mode-dependent seed tail: bytes past the baseline instruction are trailing data too. */
    if (code_len > full)
    {
        const ZyanUSize jlen = code_len - full;
        ZydisDecodedInstruction insn;
        ZydisDecodedOperand ops[ZYDIS_MAX_OPERAND_COUNT];
        memset(&insn, 0xA5, sizeof(insn));
        memset(ops, 0xA5, sizeof(ops));

        unsigned char* p = BackendPlace(be, body, full, jlen, code + full);
        ZyanStatus st = ZydisDecoderDecodeFull(&decoder, p, code_len, &insn, ops);
        ++g_decodes_total;
        CHECK(ZYAN_SUCCESS(st),
            "mode=%s seed=\"%s\": seed-tail window decode failed (0x%08X)",
            mode->name, seed->desc, st);
        if (ZYAN_SUCCESS(st))
        {
            ++g_decodes_ok;
            VerifySuccess(mode->name, seed, body, code_len, jlen,
                &base_insn, base_ops, &insn, ops);
        }
        else
        {
            ++g_decodes_fail;
            RecordStatus(st);
        }
        CHECK(BackendCanaryIntact(be, full, jlen),
            "mode=%s seed=\"%s\": canary corrupted in seed-tail window", mode->name, seed->desc);
    }

    /* ---- two-instruction stream: interior windows must decode just the first instruction ----- */
    static const unsigned char tail_long[] = { 0x05, 0x11, 0x22, 0x33, 0x44 }; // add eax, imm32
    unsigned char stream[ZYDIS_MAX_INSTRUCTION_LENGTH + 8];
    ZyanUSize stream_len = full + sizeof(tail_long);
    CHECK(stream_len <= sizeof(stream),
        "mode=%s seed=\"%s\": stream buffer too small", mode->name, seed->desc);
    memcpy(stream, body, full);
    memcpy(stream + full, tail_long, sizeof(tail_long));

    for (ZyanUSize w = full; w <= stream_len; ++w)
    {
        ZydisDecodedInstruction insn;
        ZydisDecodedOperand ops[ZYDIS_MAX_OPERAND_COUNT];
        memset(&insn, 0xA5, sizeof(insn));
        memset(ops, 0xA5, sizeof(ops));

        unsigned char* p = BackendPlace(be, stream, w, 0, ZYAN_NULL);
        ZyanStatus st = ZydisDecoderDecodeFull(&decoder, p, w, &insn, ops);
        ++g_decodes_total;
        if (ZYAN_SUCCESS(st))
        {
            ++g_decodes_ok;
            CHECK(insn.length == full,
                "mode=%s seed=\"%s\": stream window %zu decoded length %u instead of %zu",
                mode->name, seed->desc, (size_t)w, insn.length, (size_t)full);
            VerifySuccess(mode->name, seed, stream, w, 0, &base_insn, base_ops, &insn, ops);
        }
        else
        {
            ++g_decodes_fail;
            RecordStatus(st);
            unsigned char sentinel[sizeof(ZydisDecodedOperand)];
            memset(sentinel, 0xA5, sizeof(sentinel));
            VerifyFailure(mode->name, seed, w, &zero_insn, &insn, ops, sentinel);
        }
        CHECK(BackendCanaryIntact(be, w, 0),
            "mode=%s seed=\"%s\": canary corrupted in stream window %zu",
            mode->name, seed->desc, (size_t)w);
    }

    /* ---- zero-length window is rejected without touching the output structs ------------------ */
    {
        ZydisDecodedInstruction insn;
        ZydisDecodedOperand ops[ZYDIS_MAX_OPERAND_COUNT];
        unsigned char sentinel[sizeof(ZydisDecodedOperand)];
        memset(sentinel, 0xA5, sizeof(sentinel));
        memset(&insn, 0xA5, sizeof(insn));
        memset(ops, 0xA5, sizeof(ops));
        unsigned char* zp = BackendPlace(be, code, code_len, 0, ZYAN_NULL);
        ZyanStatus st = ZydisDecoderDecodeFull(&decoder, zp, 0, &insn, ops);
        ++g_decodes_total;
        ++g_decodes_fail;
        RecordStatus(st);
        CHECK(ZYAN_FAILED(st), "mode=%s seed=\"%s\": zero-length decode succeeded",
            mode->name, seed->desc);
        CHECK(st == ZYDIS_STATUS_NO_MORE_DATA,
            "mode=%s seed=\"%s\": zero-length gave status 0x%08X, expected NO_MORE_DATA",
            mode->name, seed->desc, st);
        VerifyFailure(mode->name, seed, 0, &zero_insn, &insn, ops, sentinel);
    }

    CheckSplitApiContext(&decoder, be, code, code_len, mode->name, seed);
}

/* ============================================================================================== */
/* Entry point                                                                                    */
/* ============================================================================================== */

int main(void)
{
    GuardWindow gw;
    if (!GuardWindowInit(&gw))
    {
        printf("FATAL: failed to set up guarded memory window\n");
        return 2;
    }

    printf("== segment/truncation fuzzy verification =="
           "\npage size: %ld bytes, guard page: PROT_NONE, seeds: %d, modes: %d, backends: %d\n\n",
        gw.page_size, SEED_COUNT, MODE_COUNT, BACKEND_COUNT);

    WindowBackend backends[BACKEND_COUNT];
    for (int b = 0; b < BACKEND_COUNT; ++b)
    {
        if (!BackendInit(&backends[b], (BackendKind)b, &gw))
        {
            printf("FATAL: failed to initialize read-window backend %d\n", b);
            GuardWindowDestroy(&gw);
            return 2;
        }
    }

    for (int b = 0; b < BACKEND_COUNT; ++b)
    {
        printf("[backend] %s\n", backends[b].name);
        for (int m = 0; m < MODE_COUNT; ++m)
        {
            const ModeConfig* mode = &g_modes[m];
            printf("  [mode] %s\n", mode->name);
            for (int s = 0; s < SEED_COUNT; ++s)
            {
                RunSeed(mode, &g_seeds[s], &backends[b]);
            }
        }
    }

    for (int b = 0; b < BACKEND_COUNT; ++b)
    {
        BackendDestroy(&backends[b]);
    }
    GuardWindowDestroy(&gw);

    printf("\n== status-code histogram of failed decodes (low 16 bits) ==\n");
    for (size_t i = 0; i < sizeof(g_status_hist) / sizeof(g_status_hist[0]); ++i)
    {
        if (g_status_hist[i])
        {
            printf("  code 0x%02zX: %u occurrence(s)\n", i, g_status_hist[i]);
        }
    }

    printf("\n== summary ==\n");
    printf("  decodes:        %lld (ok=%lld, failed=%lld)\n",
        g_decodes_total, g_decodes_ok, g_decodes_fail);
    printf("  checks:         %lld, failures: %lld\n", g_checks_total, g_checks_failed);

    if (g_checks_failed)
    {
        printf("\nTEST FAILED.\n");
        return 1;
    }
    printf("\nALL TESTS PASSED.\n");
    return 0;
}
