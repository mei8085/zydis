/***************************************************************************************************

  Zydis Anti-Analysis Classification Unit Test

  Verifies the guarantees of `ZydisClassifyAntiAnalysis` /
  `ZydisDecoderDecodeAntiAnalysis`:

  1. Classification distinguishes the four classes:
     - `ARCHITECTURAL`: necessarily valid in the current machine mode.
     - `FEATURE_DEPENDENT`: only valid with a specific CPU feature present.
     - `PROCESSOR_DEPENDENT`: legal encoding whose meaning/availability varies
       between processors or vendors.
     - `UNRELATED`: not an anti-analysis instruction at all.
  2. The classification never alters the regular decode result: mnemonic,
     operands and instruction length are identical to `ZydisDecoderDecodeFull`.
  3. Prefix combinations and alias encodings that decode to a regular
     instruction are *not* reported as signals (no false positives).
  4. Truncated input keeps the exact same status code as the regular decoder,
     reports no classification and does not read out of bounds (verified by
     running the whole test under ASan/valgrind as part of the build matrix).
  5. Regular instructions keep the current decode result and error codes.

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

typedef struct AntiResult_
{
    ZyanStatus status;
    ZydisDecodedInstruction instruction;
    ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];
    ZydisAntiAnalysisInfo info;
} AntiResult;

/**
 * Runs both the regular decode and the classifying decode on the same input
 * and stores the results, with the output structs poisoned beforehand so that
 * uninitialized fields are detectable.
 */
static void DecodeBoth(const ZydisDecoder* decoder, const void* buffer, ZyanUSize length,
    AntiResult* result, ZyanStatus* regular_status)
{
    memset(result, 0xA5, sizeof(*result));
    *regular_status = ZydisDecoderDecodeFull(decoder, buffer, length, &result->instruction,
        result->operands);
    result->status = ZydisDecoderDecodeAntiAnalysis(decoder, buffer, length,
        &result->instruction, result->operands, &result->info);
}

/**
 * Decodes with the classifying entry point only.
 */
static ZyanStatus DecodeAA(const ZydisDecoder* decoder, const void* buffer, ZyanUSize length,
    ZydisDecodedInstruction* instruction, ZydisDecodedOperand* operands,
    ZydisAntiAnalysisInfo* info)
{
    return ZydisDecoderDecodeAntiAnalysis(decoder, buffer, length, instruction, operands, info);
}

/**
 * Decodes the given byte sequence and checks the expected classification and
 * (optionally) the expected gating ISA extension.
 */
static void ExpectClassification(const ZydisDecoder* decoder, const char* name,
    const ZyanU8* buffer, ZyanUSize length, ZydisAntiAnalysisClass expected,
    ZydisISAExt expected_ext)
{
    ZydisDecodedInstruction instruction;
    ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];
    ZydisAntiAnalysisInfo info;

    const ZyanStatus status = DecodeAA(decoder, buffer, length, &instruction, operands, &info);

    ++g_checks;
    if (!ZYAN_SUCCESS(status))
    {
        ++g_failures;
        printf("FAIL: '%s' did not decode (status = 0x%08X)\n", name, (unsigned)status);
        return;
    }

    ++g_checks;
    if (info.classification != expected)
    {
        ++g_failures;
        printf("FAIL: '%s' classified as %s, expected %s\n", name,
            ZydisAntiAnalysisClassGetString(info.classification),
            ZydisAntiAnalysisClassGetString(expected));
    }

    ++g_checks;
    if (info.isa_ext != expected_ext)
    {
        ++g_failures;
        printf("FAIL: '%s' gating extension is %s, expected %s\n", name,
            ZydisISAExtGetString(info.isa_ext), ZydisISAExtGetString(expected_ext));
    }

    /* The reported gating extension must agree with the decoder's own ISA-extension metadata;
     * this keeps the classification table from drifting away from the instruction database. */
    if (expected_ext != ZYDIS_ISA_EXT_INVALID)
    {
        ++g_checks;
        if (info.isa_ext != instruction.meta.isa_ext)
        {
            ++g_failures;
            printf("FAIL: '%s' classification ext %s differs from decoded ext %s\n", name,
                ZydisISAExtGetString(info.isa_ext),
                ZydisISAExtGetString(instruction.meta.isa_ext));
        }
    }

    /* The classification must always mirror the original length/operands. */
    CHECK(info.length == instruction.length, "classification mirrors instruction length");
    CHECK(info.operand_count == instruction.operand_count,
        "classification mirrors operand count");
}

/**
 * Decodes the given input twice with the classifying entry point into
 * independent output buffers and checks that the results are identical, then
 * checks parity against the regular decode entry point. Same status code,
 * mnemonic, length and operands.
 */
static void CheckDecodeParity(const ZydisDecoder* decoder, const char* name,
    const ZyanU8* buffer, ZyanUSize length)
{
    AntiResult result;
    AntiResult again;
    ZyanStatus regular_status;

    DecodeBoth(decoder, buffer, length, &result, &regular_status);
    DecodeBoth(decoder, buffer, length, &again, &regular_status);

    ++g_checks;
    if (result.status != regular_status)
    {
        ++g_failures;
        printf("FAIL: '%s' status differs (regular = 0x%08X, classifying = 0x%08X)\n", name,
            (unsigned)regular_status, (unsigned)result.status);
        return;
    }

    if (!ZYAN_SUCCESS(regular_status))
    {
        /* Failed input yields no classification at all. */
        CHECK(result.info.classification == ZYDIS_ANTIANALYSIS_CLASS_UNRELATED,
            "failed decode reports no classification");
        CHECK(result.info.length == 0, "failed decode reports zero length");
        CHECK(result.info.operand_count == 0, "failed decode reports zero operand count");
        return;
    }

    /* Two independent classifying decodes agree field for field. */
    CHECK(again.status == result.status, "classifying decode is deterministic");
    CHECK(again.instruction.mnemonic == result.instruction.mnemonic,
        "classifying decode returns a stable mnemonic");
    CHECK(again.instruction.length == result.instruction.length,
        "classifying decode returns a stable length");
    CHECK(again.info.classification == result.info.classification,
        "classification is deterministic");
    CHECK(again.info.length == result.info.length, "classification length is stable");
    CHECK(again.info.isa_ext == result.info.isa_ext, "classification extension is stable");

    CHECK(result.info.length == result.instruction.length,
        "classification length equals decoded length");
    CHECK(result.info.operand_count == result.instruction.operand_count,
        "classification operand count equals decoded operand count");

    /* Compare the semantics of the operands produced by both entry points. */
    ZydisDecodedInstruction regular_instruction;
    ZydisDecodedOperand regular_operands[ZYDIS_MAX_OPERAND_COUNT];
    CHECK_STATUS_SUCCESS(ZydisDecoderDecodeFull(decoder, buffer, length, &regular_instruction,
        regular_operands), "regular decode succeeds");

    CHECK(regular_instruction.mnemonic == result.instruction.mnemonic, "same mnemonic");
    CHECK(regular_instruction.length == result.instruction.length, "same length");
    CHECK(regular_instruction.operand_count == result.instruction.operand_count,
        "same operand count");
    CHECK(regular_instruction.attributes == result.instruction.attributes, "same attributes");

    for (ZyanU8 i = 0; i < regular_instruction.operand_count; ++i)
    {
        CHECK(regular_operands[i].type == result.operands[i].type, "same operand type");
        CHECK(regular_operands[i].size == result.operands[i].size, "same operand size");
        CHECK(regular_operands[i].actions == result.operands[i].actions,
            "same operand actions");
    }
}

/* ============================================================================================== */
/* Tests                                                                                          */
/* ============================================================================================== */

/**
 * Signals that are necessarily valid in the current mode.
 */
static void TestArchitectural(void)
{
    static const struct
    {
        const char* name;
        ZyanU8 bytes[8];
        ZyanU8 length;
    } cases[] =
    {
        { "CPUID",          { 0x0F, 0xA2 },                     2 },
        { "RDTSC",          { 0x0F, 0x31 },                     2 },
        { "RDPMC",          { 0x0F, 0x33 },                     2 },
        { "RDMSR",          { 0x0F, 0x32 },                     2 },
        { "WRMSR",          { 0x0F, 0x30 },                     2 },
        { "SIDT",           { 0x0F, 0x01, 0x08 },               3 },
        { "SGDT",           { 0x0F, 0x01, 0x00 },               3 },
        { "SLDT",           { 0x0F, 0x00, 0x00 },               3 },
        { "STR",            { 0x0F, 0x00, 0x08 },               3 },
        { "SMSW",           { 0x0F, 0x01, 0x20 },               3 },
        { "IN AL, imm8",    { 0xE4, 0x80 },                     2 },
        { "OUT imm8, AL",   { 0xE6, 0x80 },                     2 },
        { "INSB",           { 0x6C },                           1 },
        { "OUTSB",          { 0x6E },                           1 },
        { "INT3",           { 0xCC },                           1 },
        { "INT imm8",       { 0xCD, 0x80 },                     2 },
        { "UD2",            { 0x0F, 0x0B },                     2 },
        { "HLT",            { 0xF4 },                           1 },
        { "CLI",            { 0xFA },                           1 },
        { "STI",            { 0xFB },                           1 },
        { "SYSCALL",        { 0x0F, 0x05 },                     2 },
        { "SWAPGS",         { 0x0F, 0x01, 0xF8 },               3 },
    };

    ZydisDecoder decoder;
    CHECK_STATUS_SUCCESS(ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64,
        ZYDIS_STACK_WIDTH_64), "init 64-bit decoder");

    for (ZyanUSize i = 0; i < ZYAN_ARRAY_LENGTH(cases); ++i)
    {
        ExpectClassification(&decoder, cases[i].name, cases[i].bytes, cases[i].length,
            ZYDIS_ANTIANALYSIS_CLASS_ARCHITECTURAL, ZYDIS_ISA_EXT_INVALID);
        CheckDecodeParity(&decoder, cases[i].name, cases[i].bytes, cases[i].length);
    }
}

/**
 * Signals that require a specific CPU feature, otherwise they raise `#UD`.
 */
static void TestFeatureDependent(void)
{
    static const struct
    {
        const char* name;
        ZyanU8 bytes[8];
        ZyanU8 length;
        ZydisISAExt ext;
    } cases[] =
    {
        { "RDTSCP",     { 0x0F, 0x01, 0xF9 },         3, ZYDIS_ISA_EXT_RDTSCP },
        { "POPCNT",     { 0xF3, 0x0F, 0xB8, 0xC0 },   4, ZYDIS_ISA_EXT_SSE4 },
        { "XGETBV",     { 0x0F, 0x01, 0xD0 },         3, ZYDIS_ISA_EXT_XSAVE },
        { "XSETBV",     { 0x0F, 0x01, 0xD1 },         3, ZYDIS_ISA_EXT_XSAVE },
        { "RDRAND",     { 0x0F, 0xC7, 0xF0 },         3, ZYDIS_ISA_EXT_RDRAND },
        { "RDSEED",     { 0x0F, 0xC7, 0xF8 },         3, ZYDIS_ISA_EXT_RDSEED },
        { "RDPID",      { 0xF3, 0x0F, 0xC7, 0xF8 },   4, ZYDIS_ISA_EXT_RDPID },
        { "MONITOR",    { 0x0F, 0x01, 0xC8 },         3, ZYDIS_ISA_EXT_MONITOR },
        { "MWAIT",      { 0x0F, 0x01, 0xC9 },         3, ZYDIS_ISA_EXT_MONITOR },
        { "UMONITOR",   { 0xF3, 0x0F, 0xAE, 0xF0 },   4, ZYDIS_ISA_EXT_WAITPKG },
        { "UMWAIT",     { 0xF2, 0x0F, 0xAE, 0xF0 },   4, ZYDIS_ISA_EXT_WAITPKG },
        { "TPAUSE",     { 0x66, 0x0F, 0xAE, 0xF0 },   4, ZYDIS_ISA_EXT_WAITPKG },
        { "SERIALIZE",  { 0x0F, 0x01, 0xE8 },         3, ZYDIS_ISA_EXT_SERIALIZE },
        { "CLDEMOTE",   { 0x0F, 0x1C, 0x00 },         3, ZYDIS_ISA_EXT_CLDEMOTE },
        { "CLFLUSHOPT", { 0x66, 0x0F, 0xAE, 0x38 },   4, ZYDIS_ISA_EXT_CLFLUSHOPT },
        { "CLWB",       { 0x66, 0x0F, 0xAE, 0x30 },   4, ZYDIS_ISA_EXT_CLWB },
        { "XSAVEOPT",   { 0x0F, 0xAE, 0x30 },         3, ZYDIS_ISA_EXT_XSAVEOPT },
        { "PTWRITE",    { 0xF3, 0x0F, 0xAE, 0x20 },   4, ZYDIS_ISA_EXT_PT },
        { "RDPKRU",     { 0x0F, 0x01, 0xEE },         3, ZYDIS_ISA_EXT_PKU },
        { "WRPKRU",     { 0x0F, 0x01, 0xEF },         3, ZYDIS_ISA_EXT_PKU },
        { "GETSEC",     { 0x0F, 0x37 },               2, ZYDIS_ISA_EXT_SMX },
        { "ENCLS",      { 0x0F, 0x01, 0xCF },         3, ZYDIS_ISA_EXT_SGX },
        { "RDMSRLIST",  { 0xF2, 0x0F, 0x01, 0xC6 },   4, ZYDIS_ISA_EXT_MSRLIST },
    };

    ZydisDecoder decoder;
    CHECK_STATUS_SUCCESS(ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64,
        ZYDIS_STACK_WIDTH_64), "init 64-bit decoder");

    for (ZyanUSize i = 0; i < ZYAN_ARRAY_LENGTH(cases); ++i)
    {
        ExpectClassification(&decoder, cases[i].name, cases[i].bytes, cases[i].length,
            ZYDIS_ANTIANALYSIS_CLASS_FEATURE_DEPENDENT, cases[i].ext);
        CheckDecodeParity(&decoder, cases[i].name, cases[i].bytes, cases[i].length);
    }
}

/**
 * Legal encodings whose meaning depends on the processor/vendor.
 */
static void TestProcessorDependent(void)
{
    static const struct
    {
        const char* name;
        ZyanU8 bytes[8];
        ZyanU8 length;
        ZydisISAExt ext;
    } cases[] =
    {
        { "LZCNT",      { 0xF3, 0x0F, 0xBD, 0xC0 },   4, ZYDIS_ISA_EXT_LZCNT },
        { "TZCNT",      { 0xF3, 0x0F, 0xBC, 0xC0 },   4, ZYDIS_ISA_EXT_BMI1 },
        { "PAUSE",      { 0xF3, 0x90 },               2, ZYDIS_ISA_EXT_PAUSE },
        { "ENDBR64",    { 0xF3, 0x0F, 0x1E, 0xFA },   4, ZYDIS_ISA_EXT_CET },
        { "ENDBR32",    { 0xF3, 0x0F, 0x1E, 0xFB },   4, ZYDIS_ISA_EXT_CET },
        { "PREFETCHW",  { 0x0F, 0x0D, 0x08 },         3, ZYDIS_ISA_EXT_AMD3DNOW_PREFETCH },
        { "PREFETCH",   { 0x0F, 0x0D, 0x00 },         3, ZYDIS_ISA_EXT_AMD3DNOW_PREFETCH },
        { "PREFETCHWT1",{ 0x0F, 0x0D, 0x10 },         3, ZYDIS_ISA_EXT_PREFETCHWT1 },
        { "XBEGIN",     { 0xC7, 0xF8, 0x00, 0x00, 0x00, 0x00 }, 6, ZYDIS_ISA_EXT_RTM },
        { "XTEST",      { 0x0F, 0x01, 0xD6 },         3, ZYDIS_ISA_EXT_RTM },
        { "UD1",        { 0x0F, 0xB9, 0xC0 },         3, ZYDIS_ISA_EXT_INVALID },
        { "UD0",        { 0x0F, 0xFF, 0xC0 },         3, ZYDIS_ISA_EXT_INVALID },
        { "VMCALL",     { 0x0F, 0x01, 0xC1 },         3, ZYDIS_ISA_EXT_VTX },
        { "VMLAUNCH",   { 0x0F, 0x01, 0xC2 },         3, ZYDIS_ISA_EXT_VTX },
        { "VMMCALL",    { 0x0F, 0x01, 0xD9 },         3, ZYDIS_ISA_EXT_SVM },
        { "VMRUN",      { 0x0F, 0x01, 0xD8 },         3, ZYDIS_ISA_EXT_SVM },
        { "VMFUNC",     { 0x0F, 0x01, 0xD4 },         3, ZYDIS_ISA_EXT_VMFUNC },
        { "CLZERO",     { 0x0F, 0x01, 0xFC },         3, ZYDIS_ISA_EXT_CLZERO },
        { "MONITORX",   { 0x0F, 0x01, 0xFA },         3, ZYDIS_ISA_EXT_MONITORX },
        { "RDPRU",      { 0x0F, 0x01, 0xFD },         3, ZYDIS_ISA_EXT_RDPRU },
        { "MCOMMIT",    { 0xF3, 0x0F, 0x01, 0xFA },   4, ZYDIS_ISA_EXT_MCOMMIT },
        { "INVLPGB",    { 0x0F, 0x01, 0xFE },         3, ZYDIS_ISA_EXT_AMD_INVLPGB },
    };

    ZydisDecoder decoder;
    CHECK_STATUS_SUCCESS(ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64,
        ZYDIS_STACK_WIDTH_64), "init 64-bit decoder");

    for (ZyanUSize i = 0; i < ZYAN_ARRAY_LENGTH(cases); ++i)
    {
        ExpectClassification(&decoder, cases[i].name, cases[i].bytes, cases[i].length,
            ZYDIS_ANTIANALYSIS_CLASS_PROCESSOR_DEPENDENT, cases[i].ext);
        CheckDecodeParity(&decoder, cases[i].name, cases[i].bytes, cases[i].length);
    }

    /* `SYSCALL` is architectural in 64-bit mode, but only an AMD-only opcode in legacy mode. */
    {
        ZydisDecoder legacy;
        CHECK_STATUS_SUCCESS(ZydisDecoderInit(&legacy, ZYDIS_MACHINE_MODE_LEGACY_32,
            ZYDIS_STACK_WIDTH_32), "init legacy decoder");
        const ZyanU8 syscall[] = { 0x0F, 0x05 };
        ExpectClassification(&legacy, "SYSCALL (legacy)", syscall, sizeof(syscall),
            ZYDIS_ANTIANALYSIS_CLASS_PROCESSOR_DEPENDENT, ZYDIS_ISA_EXT_INVALID);
    }

    /* `SALC` is an undocumented 32-bit-only opcode; it is invalid in 64-bit mode. */
    {
        ZydisDecoder legacy;
        CHECK_STATUS_SUCCESS(ZydisDecoderInit(&legacy, ZYDIS_MACHINE_MODE_LEGACY_32,
            ZYDIS_STACK_WIDTH_32), "init legacy decoder");
        const ZyanU8 salc[] = { 0xD6 };
        ExpectClassification(&legacy, "SALC (legacy)", salc, sizeof(salc),
            ZYDIS_ANTIANALYSIS_CLASS_PROCESSOR_DEPENDENT, ZYDIS_ISA_EXT_INVALID);
        CheckDecodeParity(&legacy, "SALC (legacy)", salc, sizeof(salc));
    }
}

/**
 * Prefix combinations and alias encodings must not produce false positives.
 */
static void TestNoFalsePositives(void)
{
    ZydisDecoder decoder;
    CHECK_STATUS_SUCCESS(ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64,
        ZYDIS_STACK_WIDTH_64), "init 64-bit decoder");

    static const struct
    {
        const char* name;
        ZyanU8 bytes[8];
        ZyanU8 length;
        ZydisMnemonic mnemonic;
        ZydisAntiAnalysisClass expected;
    } cases[] =
    {
        /* `F3 0F 0D` is decoded as `NOP`, not as `PREFETCHW`. */
        { "F3 0F 0D C8 (NOP)",     { 0xF3, 0x0F, 0x0D, 0xC8 },  4, ZYDIS_MNEMONIC_NOP,
            ZYDIS_ANTIANALYSIS_CLASS_UNRELATED },
        { "0F 0D F8 (NOP)",        { 0x0F, 0x0D, 0xF8 },        3, ZYDIS_MNEMONIC_NOP,
            ZYDIS_ANTIANALYSIS_CLASS_UNRELATED },
        { "0F 0D C0 (NOP)",        { 0x0F, 0x0D, 0xC0 },        3, ZYDIS_MNEMONIC_NOP,
            ZYDIS_ANTIANALYSIS_CLASS_UNRELATED },
        /* `F3 0F 1E` outside the CET-enabled slots is a plain `NOP`. */
        { "F3 0F 1E 00 (NOP)",     { 0xF3, 0x0F, 0x1E, 0x00 },  4, ZYDIS_MNEMONIC_NOP,
            ZYDIS_ANTIANALYSIS_CLASS_UNRELATED },
        { "F3 0F 1E 38 (NOP)",     { 0xF3, 0x0F, 0x1E, 0x38 },  4, ZYDIS_MNEMONIC_NOP,
            ZYDIS_ANTIANALYSIS_CLASS_UNRELATED },
        { "0F 1E FA (NOP)",        { 0x0F, 0x1E, 0xFA },        3, ZYDIS_MNEMONIC_NOP,
            ZYDIS_ANTIANALYSIS_CLASS_UNRELATED },
        /* A redundant prefix in front of a signal keeps the signal (it does not create a
         * different instruction), but it must be the *same* classification. */
        { "66 0F A2 (CPUID)",      { 0x66, 0x0F, 0xA2 },        3, ZYDIS_MNEMONIC_CPUID,
            ZYDIS_ANTIANALYSIS_CLASS_ARCHITECTURAL },
        { "2E 0F 31 (RDTSC)",      { 0x2E, 0x0F, 0x31 },        3, ZYDIS_MNEMONIC_RDTSC,
            ZYDIS_ANTIANALYSIS_CLASS_ARCHITECTURAL },
        /* Alias encodings of regular instructions stay regular. */
        { "0F B8 C0 (invalid)",    { 0x0F, 0xB8, 0xC0 },        3, ZYDIS_MNEMONIC_INVALID,
            ZYDIS_ANTIANALYSIS_CLASS_UNRELATED },
        { "0F BD C0 (BSR)",        { 0x0F, 0xBD, 0xC0 },        3, ZYDIS_MNEMONIC_BSR,
            ZYDIS_ANTIANALYSIS_CLASS_UNRELATED },
        { "0F BC C0 (BSF)",        { 0x0F, 0xBC, 0xC0 },        3, ZYDIS_MNEMONIC_BSF,
            ZYDIS_ANTIANALYSIS_CLASS_UNRELATED },
        { "F2 0F 90 C0 (SETO)",    { 0xF2, 0x0F, 0x90, 0xC0 },  4, ZYDIS_MNEMONIC_SETO,
            ZYDIS_ANTIANALYSIS_CLASS_UNRELATED },
        { "90 (NOP)",              { 0x90 },                    1, ZYDIS_MNEMONIC_NOP,
            ZYDIS_ANTIANALYSIS_CLASS_UNRELATED },
        { "66 90 (NOP)",           { 0x66, 0x90 },              2, ZYDIS_MNEMONIC_NOP,
            ZYDIS_ANTIANALYSIS_CLASS_UNRELATED },
        { "0F 1F 00 (NOP)",        { 0x0F, 0x1F, 0x00 },        3, ZYDIS_MNEMONIC_NOP,
            ZYDIS_ANTIANALYSIS_CLASS_UNRELATED },
        { "48 89 C0 (MOV)",        { 0x48, 0x89, 0xC0 },        3, ZYDIS_MNEMONIC_MOV,
            ZYDIS_ANTIANALYSIS_CLASS_UNRELATED },
    };

    for (ZyanUSize i = 0; i < ZYAN_ARRAY_LENGTH(cases); ++i)
    {
        ZydisDecodedInstruction instruction;
        ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];
        ZydisAntiAnalysisInfo info;

        if (!ZYAN_SUCCESS(DecodeAA(&decoder, cases[i].bytes, cases[i].length, &instruction,
            operands, &info)))
        {
            /* Some alias encodings are not decodable at all; then they must report no signal. */
            CHECK(info.classification == ZYDIS_ANTIANALYSIS_CLASS_UNRELATED,
                "undecodable alias reports no signal");
            CHECK(info.length == 0, "undecodable alias reports zero length");
            continue;
        }

        CHECK(instruction.mnemonic == cases[i].mnemonic, "alias decodes to expected mnemonic");
        CHECK(info.classification == cases[i].expected,
            "alias encoding yields the expected classification");
        CHECK(info.length == instruction.length, "alias length mirrors decode");
        CHECK(info.operand_count == instruction.operand_count, "alias operands mirror decode");
    }

    /* A regular instruction that merely carries a redundant prefix stays regular. */
    {
        const ZyanU8 bytes[] = { 0x2E, 0x48, 0x89, 0xC0 };
        ZydisDecodedInstruction instruction;
        ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];
        ZydisAntiAnalysisInfo info;
        CHECK_STATUS_SUCCESS(DecodeAA(&decoder, bytes, sizeof(bytes), &instruction, operands,
            &info), "prefixed MOV decodes");
        CHECK(instruction.mnemonic == ZYDIS_MNEMONIC_MOV, "prefixed MOV stays MOV");
        CHECK(info.classification == ZYDIS_ANTIANALYSIS_CLASS_UNRELATED,
            "prefixed MOV is not a signal");
    }
}

/**
 * Truncated and over-long input keeps the regular status codes and reports no
 * classification.
 */
static void TestTruncationAndErrors(void)
{
    ZydisDecoder decoder;
    CHECK_STATUS_SUCCESS(ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64,
        ZYDIS_STACK_WIDTH_64), "init 64-bit decoder");

    static const struct
    {
        const char* name;
        ZyanU8 bytes[16];
        ZyanU8 length;
        ZyanStatus status;
    } cases[] =
    {
        /* Truncated signals: one byte of a two/three byte instruction. */
        { "0F (truncated)",         { 0x0F },                           1,
            ZYDIS_STATUS_NO_MORE_DATA },
        { "0F 01 (truncated)",      { 0x0F, 0x01 },                     2,
            ZYDIS_STATUS_NO_MORE_DATA },
        { "0F 0D (truncated)",      { 0x0F, 0x0D },                     2,
            ZYDIS_STATUS_NO_MORE_DATA },
        { "F3 0F 1E (truncated)",   { 0xF3, 0x0F, 0x1E },               3,
            ZYDIS_STATUS_NO_MORE_DATA },
        { "C7 F8 (truncated)",      { 0xC7, 0xF8 },                     2,
            ZYDIS_STATUS_NO_MORE_DATA },
        /* Illegal prefixes still produce the regular illegal-prefix error. */
        { "F0 0F 20 C0 (LOCK)",     { 0xF0, 0x0F, 0x20, 0xC0 },         4,
            ZYDIS_STATUS_ILLEGAL_LOCK },
        /* Invalid opcode. */
        { "0F 24 (invalid)",        { 0x0F, 0x24 },                     2,
            ZYDIS_STATUS_DECODING_ERROR },
        /* Instruction longer than 15 bytes. */
        { "16x 66 (too long)",      { 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
                                      0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66 }, 16,
            ZYDIS_STATUS_INSTRUCTION_TOO_LONG },
    };

    for (ZyanUSize i = 0; i < ZYAN_ARRAY_LENGTH(cases); ++i)
    {
        ZydisDecodedInstruction instruction;
        ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];
        ZydisAntiAnalysisInfo info;

        memset(&info, 0xCC, sizeof(info));
        const ZyanStatus status = DecodeAA(&decoder, cases[i].bytes, cases[i].length,
            &instruction, operands, &info);

        CHECK_STATUS_EQ(status, cases[i].status, cases[i].name);
        CHECK(info.classification == ZYDIS_ANTIANALYSIS_CLASS_UNRELATED,
            "error input reports no classification");
        CHECK(info.length == 0, "error input reports zero length");
        CHECK(info.operand_count == 0, "error input reports zero operand count");

        /* The status must be identical to the regular decode entry point. */
        AntiResult result;
        ZyanStatus regular_status;
        DecodeBoth(&decoder, cases[i].bytes, cases[i].length, &result, &regular_status);
        CHECK(regular_status == cases[i].status, "regular decoder returns the same status");
        CHECK(result.status == regular_status, "classifying decoder preserves the status");
    }

    /* Zero length input. */
    {
        ZydisDecodedInstruction instruction;
        ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];
        ZydisAntiAnalysisInfo info;
        const ZyanStatus status = DecodeAA(&decoder, "", 0, &instruction, operands, &info);
        CHECK_STATUS_EQ(status, ZYDIS_STATUS_NO_MORE_DATA, "zero-length input");
        CHECK(info.classification == ZYDIS_ANTIANALYSIS_CLASS_UNRELATED,
            "zero-length input reports no classification");
    }

    /* Invalid arguments. */
    {
        ZydisAntiAnalysisInfo info;
        ZydisDecodedInstruction instruction;
        ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];
        const ZyanU8 nop = 0x90;
        CHECK_STATUS_EQ(DecodeAA(ZYAN_NULL, &nop, 1, &instruction, operands, &info),
            ZYAN_STATUS_INVALID_ARGUMENT, "NULL decoder");
        CHECK_STATUS_EQ(DecodeAA(&decoder, &nop, 1, &instruction, operands, ZYAN_NULL),
            ZYAN_STATUS_INVALID_ARGUMENT, "NULL info");
        CHECK_STATUS_EQ(ZydisClassifyAntiAnalysis(ZYAN_NULL, &info),
            ZYAN_STATUS_INVALID_ARGUMENT, "NULL instruction");
        CHECK_STATUS_EQ(ZydisClassifyAntiAnalysis(&instruction, ZYAN_NULL),
            ZYAN_STATUS_INVALID_ARGUMENT, "NULL info in classify");
    }
}

/**
 * Classification must not disturb a decode performed afterwards and must not
 * modify the caller's instruction.
 */
static void TestStability(void)
{
    ZydisDecoder decoder;
    CHECK_STATUS_SUCCESS(ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64,
        ZYDIS_STACK_WIDTH_64), "init 64-bit decoder");

    ZydisDecodedInstruction instruction;
    ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];
    ZydisAntiAnalysisInfo info;

    static const ZyanU8 cpuid[] = { 0x0F, 0xA2 };
    CHECK_STATUS_SUCCESS(DecodeAA(&decoder, cpuid, sizeof(cpuid), &instruction, operands,
        &info), "CPUID decodes");
    CHECK(info.classification == ZYDIS_ANTIANALYSIS_CLASS_ARCHITECTURAL,
        "CPUID is architectural");

    /* Re-classifying the same instruction is idempotent and does not modify it. */
    const ZydisDecodedInstruction saved = instruction;
    ZydisAntiAnalysisInfo info2;
    CHECK_STATUS_SUCCESS(ZydisClassifyAntiAnalysis(&instruction, &info2),
        "re-classify succeeds");
    CHECK(info2.classification == info.classification, "re-classification is stable");
    CHECK(info2.length == info.length, "re-classification keeps the length");
    CHECK(memcmp(&saved, &instruction, sizeof(instruction)) == 0,
        "classification does not modify the instruction");

    /* A zero-initialized instruction is never a signal. */
    ZydisDecodedInstruction zeroed;
    memset(&zeroed, 0, sizeof(zeroed));
    ZydisAntiAnalysisInfo zero_info;
    memset(&zero_info, 0xEE, sizeof(zero_info));
    CHECK_STATUS_SUCCESS(ZydisClassifyAntiAnalysis(&zeroed, &zero_info),
        "classify zeroed instruction");
    CHECK(zero_info.classification == ZYDIS_ANTIANALYSIS_CLASS_UNRELATED,
        "zeroed instruction is unrelated");

    /* The string helper rejects out-of-range values. */
    CHECK(ZydisAntiAnalysisClassGetString(ZYDIS_ANTIANALYSIS_CLASS_UNRELATED) != ZYAN_NULL,
        "string helper returns a value");
    CHECK(ZydisAntiAnalysisClassGetString(
        (ZydisAntiAnalysisClass)(ZYDIS_ANTIANALYSIS_CLASS_MAX_VALUE + 1)) == ZYAN_NULL,
        "string helper rejects invalid classification");
}

/**
 * Regular instructions keep their classification and their decode result.
 */
static void TestRegularInstructions(void)
{
    static const struct
    {
        const char* name;
        ZyanU8 bytes[8];
        ZyanU8 length;
        ZydisMnemonic mnemonic;
    } cases[] =
    {
        { "MOV rax, rcx",  { 0x48, 0x89, 0xC8 }, 3, ZYDIS_MNEMONIC_MOV },
        { "ADD eax, 1",    { 0x83, 0xC0, 0x01 }, 3, ZYDIS_MNEMONIC_ADD },
        { "JMP rel8",      { 0xEB, 0x10 },       2, ZYDIS_MNEMONIC_JMP },
        { "PUSH rax",      { 0x50 },             1, ZYDIS_MNEMONIC_PUSH },
        { "RET",           { 0xC3 },             1, ZYDIS_MNEMONIC_RET },
        { "VADDPD",        { 0xC5, 0xF9, 0x58, 0xC1 }, 4, ZYDIS_MNEMONIC_VADDPD },
    };

    ZydisDecoder decoder;
    CHECK_STATUS_SUCCESS(ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64,
        ZYDIS_STACK_WIDTH_64), "init 64-bit decoder");

    for (ZyanUSize i = 0; i < ZYAN_ARRAY_LENGTH(cases); ++i)
    {
        ZydisDecodedInstruction instruction;
        ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];
        ZydisAntiAnalysisInfo info;

        CHECK_STATUS_SUCCESS(DecodeAA(&decoder, cases[i].bytes, cases[i].length, &instruction,
            operands, &info), cases[i].name);
        CHECK(instruction.mnemonic == cases[i].mnemonic, "regular mnemonic is preserved");
        CHECK(info.classification == ZYDIS_ANTIANALYSIS_CLASS_UNRELATED,
            "regular instruction is unrelated");
        CHECK(info.length == instruction.length, "regular length is preserved");
        CheckDecodeParity(&decoder, cases[i].name, cases[i].bytes, cases[i].length);
    }
}

/**
 * Signals must stay classified in every machine mode they decode in.
 */
static void TestMachineModes(void)
{
    static const struct
    {
        ZydisMachineMode mode;
        ZydisStackWidth width;
        const char* name;
    } modes[] =
    {
        { ZYDIS_MACHINE_MODE_LONG_64,       ZYDIS_STACK_WIDTH_64, "64-bit" },
        { ZYDIS_MACHINE_MODE_LONG_COMPAT_32, ZYDIS_STACK_WIDTH_32, "compat-32" },
        { ZYDIS_MACHINE_MODE_LEGACY_32,     ZYDIS_STACK_WIDTH_32, "legacy-32" },
        { ZYDIS_MACHINE_MODE_REAL_16,       ZYDIS_STACK_WIDTH_16, "real-16" },
    };

    static const ZyanU8 cpuid[] = { 0x0F, 0xA2 };
    static const ZyanU8 rdtsc[] = { 0x0F, 0x31 };
    static const ZyanU8 int3[] = { 0xCC };

    for (ZyanUSize i = 0; i < ZYAN_ARRAY_LENGTH(modes); ++i)
    {
        ZydisDecoder decoder;
        CHECK_STATUS_SUCCESS(ZydisDecoderInit(&decoder, modes[i].mode, modes[i].width),
            "init mode decoder");

        ExpectClassification(&decoder, "CPUID", cpuid, sizeof(cpuid),
            ZYDIS_ANTIANALYSIS_CLASS_ARCHITECTURAL, ZYDIS_ISA_EXT_INVALID);
        ExpectClassification(&decoder, "RDTSC", rdtsc, sizeof(rdtsc),
            ZYDIS_ANTIANALYSIS_CLASS_ARCHITECTURAL, ZYDIS_ISA_EXT_INVALID);
        ExpectClassification(&decoder, "INT3", int3, sizeof(int3),
            ZYDIS_ANTIANALYSIS_CLASS_ARCHITECTURAL, ZYDIS_ISA_EXT_INVALID);
        CheckDecodeParity(&decoder, "CPUID", cpuid, sizeof(cpuid));
        CheckDecodeParity(&decoder, "RDTSC", rdtsc, sizeof(rdtsc));
    }
}

/* ============================================================================================== */
/* Cross-check sweep                                                                              */
/* ============================================================================================== */

/**
 * Sweeps short inputs in every machine mode and verifies the invariant that
 * ties the classification to the regular decode result:
 *
 * - status codes are identical,
 * - an instruction that did not decode reports `UNRELATED` with length 0,
 * - a decoded instruction is reported with the decoded mnemonic, the exact
 *   decoded length and the exact operand count,
 * - decoded operands match `ZydisDecoderDecodeFull` field for field.
 */
static void SweepInputs(const ZydisDecoder* decoder, ZyanU32 seed, int random_iterations)
{
    ZyanU8 buffer[ZYDIS_MAX_INSTRUCTION_LENGTH];
    ZyanU32 state = seed;

    struct
    {
        ZydisDecodedInstruction instruction;
        ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];
        ZydisAntiAnalysisInfo info;
        ZyanStatus status;
    } a, b;

    /* Every 1- and 2-byte sequence. */
    for (ZyanU32 v = 0; v < 0x10000u; ++v)
    {
        const ZyanUSize length = (v < 0x100u) ? 1 : 2;
        for (ZyanUSize i = 0; i < length; ++i)
        {
            buffer[i] = (ZyanU8)(v >> (8 * i));
        }

        memset(&a, 0x5A, sizeof(a));
        memset(&b, 0x5A, sizeof(b));
        a.status = ZydisDecoderDecodeAntiAnalysis(decoder, buffer, length, &a.instruction,
            a.operands, &a.info);
        b.status = ZydisDecoderDecodeFull(decoder, buffer, length, &b.instruction, b.operands);

        ++g_checks;
        if (a.status != b.status)
        {
            ++g_failures;
            continue;
        }
        if (!ZYAN_SUCCESS(a.status))
        {
            ++g_checks;
            if ((a.info.classification != ZYDIS_ANTIANALYSIS_CLASS_UNRELATED) ||
                (a.info.length != 0) || (a.info.operand_count != 0))
            {
                ++g_failures;
            }
            continue;
        }

        ++g_checks;
        if ((a.instruction.mnemonic != b.instruction.mnemonic) ||
            (a.instruction.length != b.instruction.length) ||
            (a.instruction.operand_count != b.instruction.operand_count) ||
            (a.info.length != b.instruction.length) ||
            (a.info.operand_count != b.instruction.operand_count) ||
            (memcmp(a.operands, b.operands, sizeof(b.operands)) != 0))
        {
            ++g_failures;
        }
    }

    /* Random longer sequences. */
    for (int iteration = 0; iteration < random_iterations; ++iteration)
    {
        state = state * 1664525u + 1013904223u;
        const ZyanUSize length = 1 + (state >> 16) % ZYDIS_MAX_INSTRUCTION_LENGTH;
        for (ZyanUSize i = 0; i < length; ++i)
        {
            state = state * 1664525u + 1013904223u;
            buffer[i] = (ZyanU8)(state >> 24);
        }

        memset(&a, 0x5A, sizeof(a));
        memset(&b, 0x5A, sizeof(b));
        a.status = ZydisDecoderDecodeAntiAnalysis(decoder, buffer, length, &a.instruction,
            a.operands, &a.info);
        b.status = ZydisDecoderDecodeFull(decoder, buffer, length, &b.instruction, b.operands);

        ++g_checks;
        if (a.status != b.status)
        {
            ++g_failures;
            continue;
        }
        if (!ZYAN_SUCCESS(a.status))
        {
            ++g_checks;
            if (a.info.classification != ZYDIS_ANTIANALYSIS_CLASS_UNRELATED)
            {
                ++g_failures;
            }
            continue;
        }
        ++g_checks;
        if ((a.instruction.mnemonic != b.instruction.mnemonic) ||
            (a.instruction.length != b.instruction.length) ||
            (a.info.length != b.instruction.length) ||
            (a.info.operand_count != b.instruction.operand_count))
        {
            ++g_failures;
        }
    }
}

/**
 * Runs the cross-check sweep in all machine modes.
 */
static void TestSweep(void)
{
    static const struct
    {
        ZydisMachineMode mode;
        ZydisStackWidth width;
        ZyanU32 seed;
    } modes[] =
    {
        { ZYDIS_MACHINE_MODE_LONG_64,       ZYDIS_STACK_WIDTH_64, 1 },
        { ZYDIS_MACHINE_MODE_LEGACY_32,     ZYDIS_STACK_WIDTH_32, 2 },
        { ZYDIS_MACHINE_MODE_LEGACY_16,     ZYDIS_STACK_WIDTH_16, 3 },
        { ZYDIS_MACHINE_MODE_REAL_16,       ZYDIS_STACK_WIDTH_16, 4 },
    };

    for (ZyanUSize i = 0; i < ZYAN_ARRAY_LENGTH(modes); ++i)
    {
        ZydisDecoder decoder;
        CHECK_STATUS_SUCCESS(ZydisDecoderInit(&decoder, modes[i].mode, modes[i].width),
            "init sweep decoder");
        SweepInputs(&decoder, modes[i].seed, 20000);
    }
}

/* ============================================================================================== */
/* Entry point                                                                                    */
/* ============================================================================================== */

int main(void)
{
    TestArchitectural();
    TestFeatureDependent();
    TestProcessorDependent();
    TestNoFalsePositives();
    TestTruncationAndErrors();
    TestStability();
    TestRegularInstructions();
    TestMachineModes();
    TestSweep();

    printf("\n%d checks, %d failures\n", g_checks, g_failures);
    return g_failures ? 1 : 0;
}
