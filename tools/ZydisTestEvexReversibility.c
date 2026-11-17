/***************************************************************************************************

  ZydisTestEvexReversibility.c

  Integration tests that verify the reversibility of EVEX instructions combining
  masking, zeroing, embedded broadcast and compressed (disp8*N) displacements.

  The test suite is split into three sections:

    1. Valid samples are decoded, converted to an encoder request and re-encoded.
       The re-encoded bytes are decoded again and the full decoder state (including
       implicit operands) is compared against the original decode. Mask semantics,
       memory widths and addressing meaning must survive the round trip, and the
       formatted Intel/AT&T text must be identical for both decodes. Re-encoding
       must be a fixed point.

    2. Illegal EVEX combinations (zeroing without a mask, missing mandatory masks,
       invalid vector lengths, ...) must be rejected with an explicit status code.
       Rejected input must neither leave visible decoder state behind nor be
       renderable or re-encodable as an executable instruction.

    3. Machine-mode changes on the encoder request must either be rejected
       explicitly (without touching the output buffer) or produce bytes that keep
       the original operand semantics - operands must never be silently rewritten.

  All byte samples are small, locally defined fixtures.

****************************************************************************************************/

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include <Zydis/Zydis.h>

/* ============================================================================================== */
/* Constants                                                                                      */
/* ============================================================================================== */

/**
 * Runtime address used for formatting and absolute-address calculations.
 */
#define TEST_RUNTIME_ADDRESS 0x4000ULL

/**
 * Fill pattern used to detect output-buffer modifications on failed encodes.
 */
#define TEST_BUFFER_SENTINEL 0xA5

#define TEST_ARRAY_SIZE(array) (sizeof(array) / sizeof((array)[0]))

/* ============================================================================================== */
/* Test fixture types                                                                             */
/* ============================================================================================== */

/**
 * A decoded instruction together with its raw bytes, operands and formatted text.
 */
typedef struct TestInstruction_
{
    ZyanU8 bytes[256];
    ZyanUSize length;
    ZydisDecodedInstruction instruction;
    ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];
    char text_intel[256];
    char text_att[256];
} TestInstruction;

/**
 * EVEX-related decoder features expected for a valid sample.
 */
typedef struct ExpectedEvexFeatures_
{
    ZydisMaskMode mask_mode;
    ZydisRegister mask_reg;
    ZyanBool zeroing;
    ZydisBroadcastMode broadcast;
    ZyanBool broadcast_is_static;
    ZydisRoundingMode rounding;
    ZyanBool sae;
    ZyanU16 vector_length;
    ZyanU16 mem_size;
    ZyanU16 mem_element_size;
    ZyanU8 operand_count_visible;
    ZyanU8 operand_count;
    ZyanU8 disp_size;
} ExpectedEvexFeatures;

/**
 * A valid instruction that must survive the decode/re-encode/format round trip.
 */
typedef struct ValidCase_
{
    const char* name;
    const char* bytes;
    ZydisMachineMode machine_mode;
    const char* mnemonic;
    ExpectedEvexFeatures expected;
    const char* text_intel;
    const char* text_att;
} ValidCase;

/**
 * An illegal combination that the decoder must reject with an explicit status.
 */
typedef struct InvalidCase_
{
    const char* name;
    const char* bytes;
    ZydisMachineMode machine_mode;
    ZyanStatus status;
} InvalidCase;

/**
 * A machine-mode change applied to the encoder request of a decoded instruction.
 */
typedef struct ModeChangeCase_
{
    const char* name;
    const char* bytes;
    ZydisMachineMode source_mode;
    ZydisMachineMode target_mode;
    ZyanBool clear_size_hints;
    ZyanBool expect_accepted;
    const char* text_intel;
    const char* text_att;
} ModeChangeCase;

/* ============================================================================================== */
/* Test fixtures                                                                                  */
/* ============================================================================================== */

static const ValidCase VALID_CASES[] =
{
    {
        "merge-mask-reg", "62F17C4958C0", ZYDIS_MACHINE_MODE_LONG_64, "vaddps",
        {
            ZYDIS_MASK_MODE_MERGING, ZYDIS_REGISTER_K1, ZYAN_FALSE,
            ZYDIS_BROADCAST_MODE_NONE, ZYAN_FALSE, ZYDIS_ROUNDING_MODE_NONE, ZYAN_FALSE,
            512, 0, 0, 4, 4, 0
        },
        "vaddps zmm0 {k1}, zmm0, zmm0",
        "vaddps %zmm0, %zmm0, %zmm0 {%k1}"
    },
    {
        "zero-mask-reg", "62F17CCB58C0", ZYDIS_MACHINE_MODE_LONG_64, "vaddps",
        {
            ZYDIS_MASK_MODE_ZEROING, ZYDIS_REGISTER_K3, ZYAN_TRUE,
            ZYDIS_BROADCAST_MODE_NONE, ZYAN_FALSE, ZYDIS_ROUNDING_MODE_NONE, ZYAN_FALSE,
            512, 0, 0, 4, 4, 0
        },
        "vaddps zmm0 {k3} {z}, zmm0, zmm0",
        "vaddps %zmm0, %zmm0, %zmm0 {%k3} {z}"
    },
    {
        "merge-mask-disp8", "62F17C4958407F", ZYDIS_MACHINE_MODE_LONG_64, "vaddps",
        {
            ZYDIS_MASK_MODE_MERGING, ZYDIS_REGISTER_K1, ZYAN_FALSE,
            ZYDIS_BROADCAST_MODE_NONE, ZYAN_FALSE, ZYDIS_ROUNDING_MODE_NONE, ZYAN_FALSE,
            512, 512, 32, 4, 4, 8
        },
        "vaddps zmm0 {k1}, zmm0, zmmword ptr ds:[rax+0x1FC0]",
        "vaddpsz %ds:0x1FC0(%rax), %zmm0, %zmm0 {%k1}"
    },
    {
        "zero-mask-disp8", "62F17CC958407F", ZYDIS_MACHINE_MODE_LONG_64, "vaddps",
        {
            ZYDIS_MASK_MODE_ZEROING, ZYDIS_REGISTER_K1, ZYAN_TRUE,
            ZYDIS_BROADCAST_MODE_NONE, ZYAN_FALSE, ZYDIS_ROUNDING_MODE_NONE, ZYAN_FALSE,
            512, 512, 32, 4, 4, 8
        },
        "vaddps zmm0 {k1} {z}, zmm0, zmmword ptr ds:[rax+0x1FC0]",
        "vaddpsz %ds:0x1FC0(%rax), %zmm0, %zmm0 {%k1} {z}"
    },
    {
        "zero-bcast-disp8", "621155BDDB71F8", ZYDIS_MACHINE_MODE_LONG_64, "vpandd",
        {
            ZYDIS_MASK_MODE_ZEROING, ZYDIS_REGISTER_K5, ZYAN_TRUE,
            ZYDIS_BROADCAST_MODE_1_TO_8, ZYAN_FALSE, ZYDIS_ROUNDING_MODE_NONE, ZYAN_FALSE,
            256, 32, 32, 4, 4, 8
        },
        "vpandd ymm14 {k5} {z}, ymm5, dword ptr ds:[r9-0x20] {1to8}",
        "vpanddl %ds:-0x20(%r9) {1to8}, %ymm5, %ymm14 {%k5} {z}"
    },
    {
        "bcast-disp8", "62F1ED5B58407F", ZYDIS_MACHINE_MODE_LONG_64, "vaddpd",
        {
            ZYDIS_MASK_MODE_MERGING, ZYDIS_REGISTER_K3, ZYAN_FALSE,
            ZYDIS_BROADCAST_MODE_1_TO_8, ZYAN_FALSE, ZYDIS_ROUNDING_MODE_NONE, ZYAN_FALSE,
            512, 64, 64, 4, 4, 8
        },
        "vaddpd zmm0 {k3}, zmm2, qword ptr ds:[rax+0x3F8] {1to8}",
        "vaddpdq %ds:0x3F8(%rax) {1to8}, %zmm2, %zmm0 {%k3}"
    },
    {
        "bcast-zero-disp8", "62F1EDDB58407F", ZYDIS_MACHINE_MODE_LONG_64, "vaddpd",
        {
            ZYDIS_MASK_MODE_ZEROING, ZYDIS_REGISTER_K3, ZYAN_TRUE,
            ZYDIS_BROADCAST_MODE_1_TO_8, ZYAN_FALSE, ZYDIS_ROUNDING_MODE_NONE, ZYAN_FALSE,
            512, 64, 64, 4, 4, 8
        },
        "vaddpd zmm0 {k3} {z}, zmm2, qword ptr ds:[rax+0x3F8] {1to8}",
        "vaddpdq %ds:0x3F8(%rax) {1to8}, %zmm2, %zmm0 {%k3} {z}"
    },
    {
        "bcast-128-disp8", "62F17C1958407F", ZYDIS_MACHINE_MODE_LONG_64, "vaddps",
        {
            ZYDIS_MASK_MODE_MERGING, ZYDIS_REGISTER_K1, ZYAN_FALSE,
            ZYDIS_BROADCAST_MODE_1_TO_4, ZYAN_FALSE, ZYDIS_ROUNDING_MODE_NONE, ZYAN_FALSE,
            128, 32, 32, 4, 4, 8
        },
        "vaddps xmm0 {k1}, xmm0, dword ptr ds:[rax+0x1FC] {1to4}",
        "vaddpsl %ds:0x1FC(%rax) {1to4}, %xmm0, %xmm0 {%k1}"
    },
    {
        "static-bcast-disp8", "62F27D08784810", ZYDIS_MACHINE_MODE_LONG_64, "vpbroadcastb",
        {
            ZYDIS_MASK_MODE_DISABLED, ZYDIS_REGISTER_K0, ZYAN_FALSE,
            ZYDIS_BROADCAST_MODE_1_TO_16, ZYAN_TRUE, ZYDIS_ROUNDING_MODE_NONE, ZYAN_FALSE,
            128, 8, 8, 3, 3, 8
        },
        "vpbroadcastb xmm1, byte ptr ds:[rax+0x10]",
        "vpbroadcastbb %ds:0x10(%rax), %xmm1"
    },
    {
        "round-sae-merge", "62F1FD7958C0", ZYDIS_MACHINE_MODE_LONG_64, "vaddpd",
        {
            ZYDIS_MASK_MODE_MERGING, ZYDIS_REGISTER_K1, ZYAN_FALSE,
            ZYDIS_BROADCAST_MODE_NONE, ZYAN_FALSE, ZYDIS_ROUNDING_MODE_RZ, ZYAN_TRUE,
            512, 0, 0, 4, 4, 0
        },
        "vaddpd zmm0 {k1}, zmm0, zmm0 {rz-sae}",
        "vaddpd %zmm0 {rz-sae}, %zmm0, %zmm0 {%k1}"
    },
    {
        "implicit-flags", "62F17C182FC1", ZYDIS_MACHINE_MODE_LONG_64, "vcomiss",
        {
            ZYDIS_MASK_MODE_DISABLED, ZYDIS_REGISTER_K0, ZYAN_FALSE,
            ZYDIS_BROADCAST_MODE_NONE, ZYAN_FALSE, ZYDIS_ROUNDING_MODE_NONE, ZYAN_TRUE,
            128, 0, 0, 2, 3, 0
        },
        "vcomiss xmm0, xmm1 {sae}",
        "vcomiss %xmm1 {sae}, %xmm0"
    },
    {
        "implicit-bsr", "62F367488FCA03", ZYDIS_MACHINE_MODE_LONG_64, "top4mxbssps",
        {
            ZYDIS_MASK_MODE_DISABLED, ZYDIS_REGISTER_K0, ZYAN_FALSE,
            ZYDIS_BROADCAST_MODE_NONE, ZYAN_FALSE, ZYDIS_ROUNDING_MODE_NONE, ZYAN_FALSE,
            512, 0, 0, 4, 5, 0
        },
        "top4mxbssps tmm1, zmm2, zmm3, 0x03",
        "top4mxbssps $0x03, %zmm3, %zmm2, %tmm1"
    },
    {
        "implicit-flags-disp8", "62EC7E08F06510", ZYDIS_MACHINE_MODE_LONG_64, "invept",
        {
            ZYDIS_MASK_MODE_DISABLED, ZYDIS_REGISTER_K0, ZYAN_FALSE,
            ZYDIS_BROADCAST_MODE_NONE, ZYAN_FALSE, ZYDIS_ROUNDING_MODE_NONE, ZYAN_FALSE,
            128, 128, 128, 2, 3, 8
        },
        "invept r20, xmmword ptr ds:[r21+0x10]",
        "inveptx %ds:0x10(%r21), %r20"
    },
    {
        "rip-relative", "62F17C49580510000000", ZYDIS_MACHINE_MODE_LONG_64, "vaddps",
        {
            ZYDIS_MASK_MODE_MERGING, ZYDIS_REGISTER_K1, ZYAN_FALSE,
            ZYDIS_BROADCAST_MODE_NONE, ZYAN_FALSE, ZYDIS_ROUNDING_MODE_NONE, ZYAN_FALSE,
            512, 512, 32, 4, 4, 32
        },
        "vaddps zmm0 {k1}, zmm0, zmmword ptr ds:[0x000000000000401A]",
        "vaddpsz %ds:0x000000000000401A, %zmm0, %zmm0 {%k1}"
    },
    {
        "masked-store", "62F17C492911", ZYDIS_MACHINE_MODE_LONG_64, "vmovaps",
        {
            ZYDIS_MASK_MODE_MERGING, ZYDIS_REGISTER_K1, ZYAN_FALSE,
            ZYDIS_BROADCAST_MODE_NONE, ZYAN_FALSE, ZYDIS_ROUNDING_MODE_NONE, ZYAN_FALSE,
            512, 512, 32, 3, 3, 0
        },
        "vmovaps zmmword ptr ds:[rcx] {k1}, zmm2",
        "vmovapsz %zmm2, %ds:(%rcx) {%k1}"
    },
    {
        "gather-vsib", "62F27D49920C90", ZYDIS_MACHINE_MODE_LONG_64, "vgatherdps",
        {
            ZYDIS_MASK_MODE_MERGING, ZYDIS_REGISTER_K1, ZYAN_FALSE,
            ZYDIS_BROADCAST_MODE_NONE, ZYAN_FALSE, ZYDIS_ROUNDING_MODE_NONE, ZYAN_FALSE,
            512, 32, 32, 3, 3, 0
        },
        "vgatherdps zmm1 {k1}, dword ptr ds:[rax+zmm2*4]",
        "vgatherdps %ds:(%rax,%zmm2,4), %zmm1 {%k1}"
    },
    {
        "narrow-mem-imm", "6223CD4F3A55E34F", ZYDIS_MACHINE_MODE_LONG_64, "vinserti64x4",
        {
            ZYDIS_MASK_MODE_MERGING, ZYDIS_REGISTER_K7, ZYAN_FALSE,
            ZYDIS_BROADCAST_MODE_NONE, ZYAN_FALSE, ZYDIS_ROUNDING_MODE_NONE, ZYAN_FALSE,
            512, 256, 64, 5, 5, 8
        },
        "vinserti64x4 zmm26 {k7}, zmm6, ymmword ptr ss:[rbp-0x3A0], 0x4F",
        "vinserti64x4y $0x4F, %ss:-0x3A0(%rbp), %zmm6, %zmm26 {%k7}"
    },
    {
        "disp8-32bit", "62F17C4958407F", ZYDIS_MACHINE_MODE_LONG_COMPAT_32, "vaddps",
        {
            ZYDIS_MASK_MODE_MERGING, ZYDIS_REGISTER_K1, ZYAN_FALSE,
            ZYDIS_BROADCAST_MODE_NONE, ZYAN_FALSE, ZYDIS_ROUNDING_MODE_NONE, ZYAN_FALSE,
            512, 512, 32, 4, 4, 8
        },
        "vaddps zmm0 {k1}, zmm0, zmmword ptr ds:[eax+0x1FC0]",
        "vaddpsz %ds:0x1FC0(%eax), %zmm0, %zmm0 {%k1}"
    },
    {
        "disp8-16bit", "62F17C4958407F", ZYDIS_MACHINE_MODE_LONG_COMPAT_16, "vaddps",
        {
            ZYDIS_MASK_MODE_MERGING, ZYDIS_REGISTER_K1, ZYAN_FALSE,
            ZYDIS_BROADCAST_MODE_NONE, ZYAN_FALSE, ZYDIS_ROUNDING_MODE_NONE, ZYAN_FALSE,
            512, 512, 32, 4, 4, 8
        },
        "vaddps zmm0 {k1}, zmm0, zmmword ptr ds:[bx+si*1+0x1FC0]",
        "vaddpsz %ds:0x1FC0(%bx,%si,1), %zmm0, %zmm0 {%k1}"
    },
    {
        "absolute-32bit", "62F17C4958042578563412", ZYDIS_MACHINE_MODE_LONG_COMPAT_32,
        "vaddps",
        {
            ZYDIS_MASK_MODE_MERGING, ZYDIS_REGISTER_K1, ZYAN_FALSE,
            ZYDIS_BROADCAST_MODE_NONE, ZYAN_FALSE, ZYDIS_ROUNDING_MODE_NONE, ZYAN_FALSE,
            512, 512, 32, 4, 4, 32
        },
        "vaddps zmm0 {k1}, zmm0, zmmword ptr ds:[0x12345678]",
        "vaddpsz %ds:0x12345678, %zmm0, %zmm0 {%k1}"
    },
};

static const InvalidCase INVALID_CASES[] =
{
    /* EVEX.z set with merge-mask (`aaa` selects a mask but `z` requires zeroing semantics) */
    { "zeroing-without-mask", "62F17CC858C0", ZYDIS_MACHINE_MODE_LONG_64,
        ZYDIS_STATUS_INVALID_MASK },
    /* `vcomiss` does not accept a writemask */
    { "required-mask-missing", "62F17C092FC1", ZYDIS_MACHINE_MODE_LONG_64,
        ZYDIS_STATUS_INVALID_MASK },
    /* gathers require a non-`k0` mask */
    { "gather-mask-missing", "62F27D48920C90", ZYDIS_MACHINE_MODE_LONG_64,
        ZYDIS_STATUS_INVALID_MASK },
    /* scatters require a non-`k0` mask */
    { "scatter-mask-missing", "62F27D48910C90", ZYDIS_MACHINE_MODE_LONG_64,
        ZYDIS_STATUS_INVALID_MASK },
    /* zeroing is not defined for stores */
    { "zeroing-on-store", "62F17CCB2911", ZYDIS_MACHINE_MODE_LONG_64,
        ZYDIS_STATUS_INVALID_MASK },
    /* zeroing is not defined for instructions writing a mask register */
    { "zeroing-on-mask-destination", "62F17CCBC2C100", ZYDIS_MACHINE_MODE_LONG_64,
        ZYDIS_STATUS_INVALID_MASK },
    /* EVEX.L'L = 3 is reserved */
    { "vector-length-3", "62F17C6858C0", ZYDIS_MACHINE_MODE_LONG_64,
        ZYDIS_STATUS_MALFORMED_EVEX },
    /* EVEX.mmm = 0 is reserved */
    { "invalid-opcode-map", "62F07C4858C0", ZYDIS_MACHINE_MODE_LONG_64,
        ZYDIS_STATUS_INVALID_MAP },
    /* the broadcast bit must be clear for instructions with static broadcast */
    { "broadcast-bit-on-static-broadcast", "62F27D18784810", ZYDIS_MACHINE_MODE_LONG_64,
        ZYDIS_STATUS_DECODING_ERROR },
    /* EVEX.v' must be set outside of 64-bit mode */
    { "v4-clear-outside-64bit", "62F17C4058C0", ZYDIS_MACHINE_MODE_LONG_COMPAT_32,
        ZYDIS_STATUS_MALFORMED_EVEX },
    /* register index outside of the encodable range */
    { "invalid-register", "6276FF4895C3", ZYDIS_MACHINE_MODE_LONG_64,
        ZYDIS_STATUS_BAD_REGISTER },
    /* EVEX is not encodable in real mode */
    { "evex-in-real-16", "62F17C4858C0", ZYDIS_MACHINE_MODE_REAL_16,
        ZYDIS_STATUS_DECODING_ERROR },
    /* truncated EVEX prefix */
    { "truncated-evex-4", "62F17C48", ZYDIS_MACHINE_MODE_LONG_64,
        ZYDIS_STATUS_NO_MORE_DATA },
    /* truncated opcode */
    { "truncated-evex-5", "62F17C4858", ZYDIS_MACHINE_MODE_LONG_64,
        ZYDIS_STATUS_NO_MORE_DATA },
};

static const ModeChangeCase MODE_CHANGE_CASES[] =
{
    /* Re-encoding with a different machine mode must preserve the addressing
       meaning (address-size prefixes keep the original base/index registers). */
    {
        "disp8-32bit-to-64bit", "62F17C4958407F",
        ZYDIS_MACHINE_MODE_LONG_COMPAT_32, ZYDIS_MACHINE_MODE_LONG_64,
        ZYAN_FALSE, ZYAN_TRUE,
        "vaddps zmm0 {k1}, zmm0, zmmword ptr ds:[eax+0x1FC0]",
        "vaddpsz %ds:0x1FC0(%eax), %zmm0, %zmm0 {%k1}"
    },
    {
        "disp8-16bit-to-32bit", "62F17C4958407F",
        ZYDIS_MACHINE_MODE_LONG_COMPAT_16, ZYDIS_MACHINE_MODE_LONG_COMPAT_32,
        ZYAN_FALSE, ZYAN_TRUE,
        "vaddps zmm0 {k1}, zmm0, zmmword ptr ds:[bx+si*1+0x1FC0]",
        "vaddpsz %ds:0x1FC0(%bx,%si,1), %zmm0, %zmm0 {%k1}"
    },
    {
        "disp8-32bit-to-16bit", "62F17C4958407F",
        ZYDIS_MACHINE_MODE_LONG_COMPAT_32, ZYDIS_MACHINE_MODE_LONG_COMPAT_16,
        ZYAN_FALSE, ZYAN_TRUE,
        "vaddps zmm0 {k1}, zmm0, zmmword ptr ds:[eax+0x1FC0]",
        "vaddpsz %ds:0x1FC0(%eax), %zmm0, %zmm0 {%k1}"
    },
    {
        "bcast-zero-32bit-to-64bit", "62F1EDDB58407F",
        ZYDIS_MACHINE_MODE_LONG_COMPAT_32, ZYDIS_MACHINE_MODE_LONG_64,
        ZYAN_FALSE, ZYAN_TRUE,
        "vaddpd zmm0 {k3} {z}, zmm2, qword ptr ds:[eax+0x3F8] {1to8}",
        "vaddpdq %ds:0x3F8(%eax) {1to8}, %zmm2, %zmm0 {%k3} {z}"
    },
    {
        "bcast-128-32bit-to-64bit", "62F17C1958407F",
        ZYDIS_MACHINE_MODE_LONG_COMPAT_32, ZYDIS_MACHINE_MODE_LONG_64,
        ZYAN_FALSE, ZYAN_TRUE,
        "vaddps xmm0 {k1}, xmm0, dword ptr ds:[eax+0x1FC] {1to4}",
        "vaddpsl %ds:0x1FC(%eax) {1to4}, %xmm0, %xmm0 {%k1}"
    },
    {
        "absolute-32bit-to-64bit", "62F17C4958042578563412",
        ZYDIS_MACHINE_MODE_LONG_COMPAT_32, ZYDIS_MACHINE_MODE_LONG_64,
        ZYAN_FALSE, ZYAN_TRUE,
        "vaddps zmm0 {k1}, zmm0, zmmword ptr ds:[0x0000000012345678]",
        "vaddpsz %ds:0x0000000012345678, %zmm0, %zmm0 {%k1}"
    },
    {
        "eip-relative-32bit-to-64bit", "62F17C49580510000000",
        ZYDIS_MACHINE_MODE_LONG_COMPAT_32, ZYDIS_MACHINE_MODE_LONG_64,
        ZYAN_FALSE, ZYAN_TRUE,
        "vaddps zmm0 {k1}, zmm0, zmmword ptr ds:[0x0000000000000010]",
        "vaddpsz %ds:0x0000000000000010, %zmm0, %zmm0 {%k1}"
    },
    /* Dropping the size hints lets the encoder pick defaults for the new mode. */
    {
        "hints-cleared-64bit-to-32bit", "62F17C4958C0",
        ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_MACHINE_MODE_LONG_COMPAT_32,
        ZYAN_TRUE, ZYAN_TRUE,
        "vaddps zmm0 {k1}, zmm0, zmm0",
        "vaddps %zmm0, %zmm0, %zmm0 {%k1}"
    },
    /* The remaining mode changes must be rejected explicitly instead of
       silently rewriting the operands. */
    {
        "reg-form-64bit-to-32bit", "62F17C4958C0",
        ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_MACHINE_MODE_LONG_COMPAT_32,
        ZYAN_FALSE, ZYAN_FALSE, ZYAN_NULL, ZYAN_NULL
    },
    {
        "disp8-64bit-to-32bit", "62F17C4958407F",
        ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_MACHINE_MODE_LONG_COMPAT_32,
        ZYAN_FALSE, ZYAN_FALSE, ZYAN_NULL, ZYAN_NULL
    },
    {
        "rip-relative-64bit-to-32bit", "62F17C49580510000000",
        ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_MACHINE_MODE_LONG_COMPAT_32,
        ZYAN_FALSE, ZYAN_FALSE, ZYAN_NULL, ZYAN_NULL
    },
    {
        "masked-store-64bit-to-32bit", "62F17C492911",
        ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_MACHINE_MODE_LONG_COMPAT_32,
        ZYAN_FALSE, ZYAN_FALSE, ZYAN_NULL, ZYAN_NULL
    },
    {
        "implicit-operand-64bit-to-32bit", "62F17C182FC1",
        ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_MACHINE_MODE_LONG_COMPAT_32,
        ZYAN_FALSE, ZYAN_FALSE, ZYAN_NULL, ZYAN_NULL
    },
    {
        "broadcast-64bit-to-32bit", "62F1EDDB58407F",
        ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_MACHINE_MODE_LONG_COMPAT_32,
        ZYAN_FALSE, ZYAN_FALSE, ZYAN_NULL, ZYAN_NULL
    },
    {
        "gather-64bit-to-32bit", "62F27D49920C90",
        ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_MACHINE_MODE_LONG_COMPAT_32,
        ZYAN_FALSE, ZYAN_FALSE, ZYAN_NULL, ZYAN_NULL
    },
};

/* ============================================================================================== */
/* Helpers                                                                                        */
/* ============================================================================================== */

/**
 * Prints a test-case failure detail line to `stderr`.
 */
static void ReportFailure(const char* name, const char* format, ...)
{
    va_list args;
    va_start(args, format);
    fprintf(stderr, "    '%s': ", name);
    vfprintf(stderr, format, args);
    fputc('\n', stderr);
    va_end(args);
}

/**
 * Returns the value of a hex digit or -1 for invalid characters.
 */
static ZyanI8 HexDigitValue(char digit)
{
    if ((digit >= '0') && (digit <= '9'))
    {
        return (ZyanI8)(digit - '0');
    }
    if ((digit >= 'A') && (digit <= 'F'))
    {
        return (ZyanI8)(digit - 'A' + 10);
    }
    if ((digit >= 'a') && (digit <= 'f'))
    {
        return (ZyanI8)(digit - 'a' + 10);
    }
    return -1;
}

/**
 * Parses a hex string into a byte buffer. Returns the number of bytes or 0 on error.
 */
static ZyanUSize ParseHexBytes(const char* text, ZyanU8* buffer, ZyanUSize capacity)
{
    ZyanUSize length = 0;
    while (text[0] && text[1])
    {
        const ZyanI8 high = HexDigitValue(text[0]);
        const ZyanI8 low  = HexDigitValue(text[1]);
        if ((high < 0) || (low < 0) || (length >= capacity))
        {
            return 0;
        }
        buffer[length++] = (ZyanU8)((high << 4) | low);
        text += 2;
    }
    return text[0] ? 0 : length;
}

/**
 * Maps a machine mode to its default stack width.
 */
static ZyanBool GetStackWidth(ZydisMachineMode machine_mode, ZydisStackWidth* stack_width)
{
    switch (machine_mode)
    {
    case ZYDIS_MACHINE_MODE_LONG_64:
        *stack_width = ZYDIS_STACK_WIDTH_64;
        return ZYAN_TRUE;
    case ZYDIS_MACHINE_MODE_LONG_COMPAT_32:
    case ZYDIS_MACHINE_MODE_LEGACY_32:
        *stack_width = ZYDIS_STACK_WIDTH_32;
        return ZYAN_TRUE;
    case ZYDIS_MACHINE_MODE_LONG_COMPAT_16:
    case ZYDIS_MACHINE_MODE_LEGACY_16:
    case ZYDIS_MACHINE_MODE_REAL_16:
        *stack_width = ZYDIS_STACK_WIDTH_16;
        return ZYAN_TRUE;
    default:
        return ZYAN_FALSE;
    }
}

/**
 * Initializes a decoder for the given machine mode.
 */
static ZyanBool InitializeDecoder(ZydisDecoder* decoder, ZydisMachineMode machine_mode)
{
    ZydisStackWidth stack_width;
    if (!GetStackWidth(machine_mode, &stack_width))
    {
        return ZYAN_FALSE;
    }
    return ZYAN_SUCCESS(ZydisDecoderInit(decoder, machine_mode, stack_width));
}

/**
 * Formats an instruction with forced size/segment printing in the given style.
 */
static ZyanBool FormatInstruction(const ZydisDecodedInstruction* instruction,
    const ZydisDecodedOperand* operands, ZydisFormatterStyle style, char* buffer,
    ZyanUSize length)
{
    ZydisFormatter formatter;
    if (ZYAN_FAILED(ZydisFormatterInit(&formatter, style)) ||
        ZYAN_FAILED(ZydisFormatterSetProperty(&formatter, ZYDIS_FORMATTER_PROP_FORCE_SIZE,
            ZYAN_TRUE)) ||
        ZYAN_FAILED(ZydisFormatterSetProperty(&formatter, ZYDIS_FORMATTER_PROP_FORCE_SEGMENT,
            ZYAN_TRUE)))
    {
        return ZYAN_FALSE;
    }
    return ZYAN_SUCCESS(ZydisFormatterFormatInstruction(&formatter, instruction, operands,
        instruction->operand_count_visible, buffer, length, TEST_RUNTIME_ADDRESS, ZYAN_NULL));
}

/**
 * Decodes a raw byte sequence into a test instruction.
 */
static ZyanBool DecodeBytes(TestInstruction* decoded, ZydisMachineMode machine_mode,
    const ZyanU8* bytes, ZyanUSize length)
{
    ZydisDecoder decoder;
    if (!InitializeDecoder(&decoder, machine_mode))
    {
        return ZYAN_FALSE;
    }
    memset(decoded, 0, sizeof(*decoded));
    memcpy(decoded->bytes, bytes, length);
    decoded->length = length;
    return ZYAN_SUCCESS(ZydisDecoderDecodeFull(&decoder, decoded->bytes, decoded->length,
        &decoded->instruction, decoded->operands));
}

/**
 * Decodes a hex-encoded byte sequence into a test instruction.
 */
static ZyanBool DecodeHexCase(TestInstruction* decoded, ZydisMachineMode machine_mode,
    const char* hex)
{
    ZyanU8 bytes[256];
    const ZyanUSize length = ParseHexBytes(hex, bytes, sizeof(bytes));
    if (!length)
    {
        return ZYAN_FALSE;
    }
    return DecodeBytes(decoded, machine_mode, bytes, length);
}

/**
 * Returns ZYAN_TRUE if the instruction uses zeroing-masking.
 */
static ZyanBool IsZeroingMask(const ZydisDecodedInstruction* instruction)
{
    return (instruction->avx.mask.mode == ZYDIS_MASK_MODE_ZEROING) ||
           (instruction->avx.mask.mode == ZYDIS_MASK_MODE_CONTROL_ZEROING);
}

/**
 * Returns the first memory operand of the instruction or ZYAN_NULL.
 */
static const ZydisDecodedOperand* FindMemoryOperand(const ZydisDecodedInstruction* instruction,
    const ZydisDecodedOperand* operands)
{
    for (ZyanU8 i = 0; i < instruction->operand_count; ++i)
    {
        if (operands[i].type == ZYDIS_OPERAND_TYPE_MEMORY)
        {
            return &operands[i];
        }
    }
    return ZYAN_NULL;
}

/**
 * Returns the displacement size of the first memory operand (0 if none).
 */
static ZyanU8 GetDisplacementSize(const ZydisDecodedInstruction* instruction,
    const ZydisDecodedOperand* operands)
{
    const ZydisDecodedOperand* operand = FindMemoryOperand(instruction, operands);
    return operand ? operand->mem.disp.size : 0;
}

/**
 * Returns the compressed displacement byte of the first memory operand (0 if none).
 */
static ZyanU8 GetCompressedDispByte(const ZydisDecodedInstruction* instruction,
    const ZydisDecodedOperand* operands)
{
    const ZydisDecodedOperand* operand = FindMemoryOperand(instruction, operands);
    if (!operand || (operand->mem.disp.size != 8))
    {
        return 0;
    }
    return (ZyanU8)operand->mem.disp.value;
}

/* ============================================================================================== */
/* Instruction comparison                                                                         */
/* ============================================================================================== */

/**
 * Compares a single operand pair (including implicit operands).
 */
static ZyanBool CompareOperand(const char* name, ZyanU8 index,
    const TestInstruction* expected, const TestInstruction* actual)
{
    ZyanBool ok = ZYAN_TRUE;
    const ZydisDecodedOperand* lhs = &expected->operands[index];
    const ZydisDecodedOperand* rhs = &actual->operands[index];

    if (lhs->type != rhs->type)
    {
        ReportFailure(name, "operand %u changed its type from %u to %u", index,
            (ZyanU32)lhs->type, (ZyanU32)rhs->type);
        return ZYAN_FALSE;
    }
    if (lhs->visibility != rhs->visibility)
    {
        ReportFailure(name, "operand %u changed its visibility from %u to %u", index,
            (ZyanU32)lhs->visibility, (ZyanU32)rhs->visibility);
        ok = ZYAN_FALSE;
    }
    if (lhs->actions != rhs->actions)
    {
        ReportFailure(name, "operand %u changed its actions from 0x%X to 0x%X", index,
            (ZyanU32)lhs->actions, (ZyanU32)rhs->actions);
        ok = ZYAN_FALSE;
    }
    if ((lhs->size != rhs->size) || (lhs->element_size != rhs->element_size) ||
        (lhs->element_count != rhs->element_count) ||
        (lhs->element_type != rhs->element_type))
    {
        ReportFailure(name,
            "operand %u changed its width (size %u/%u, element %u/%u, count %u/%u, "
            "type %u/%u)", index,
            (ZyanU32)lhs->size, (ZyanU32)rhs->size,
            (ZyanU32)lhs->element_size, (ZyanU32)rhs->element_size,
            (ZyanU32)lhs->element_count, (ZyanU32)rhs->element_count,
            (ZyanU32)lhs->element_type, (ZyanU32)rhs->element_type);
        ok = ZYAN_FALSE;
    }

    switch (lhs->type)
    {
    case ZYDIS_OPERAND_TYPE_REGISTER:
        if (lhs->reg.value != rhs->reg.value)
        {
            ReportFailure(name, "operand %u changed its register from '%s' to '%s'", index,
                ZydisRegisterGetString(lhs->reg.value),
                ZydisRegisterGetString(rhs->reg.value));
            ok = ZYAN_FALSE;
        }
        break;
    case ZYDIS_OPERAND_TYPE_MEMORY:
        if ((lhs->mem.type != rhs->mem.type) || (lhs->mem.segment != rhs->mem.segment) ||
            (lhs->mem.base != rhs->mem.base) || (lhs->mem.index != rhs->mem.index) ||
            (lhs->mem.scale != rhs->mem.scale) ||
            (lhs->mem.disp.value != rhs->mem.disp.value) ||
            (lhs->mem.disp.size != rhs->mem.disp.size))
        {
            ReportFailure(name,
                "operand %u changed its addressing (type %u/%u, segment %s/%s, base %s/%s, "
                "index %s/%s, scale %u/%u, disp 0x%llX/%u vs 0x%llX/%u)", index,
                (ZyanU32)lhs->mem.type, (ZyanU32)rhs->mem.type,
                ZydisRegisterGetString(lhs->mem.segment),
                ZydisRegisterGetString(rhs->mem.segment),
                ZydisRegisterGetString(lhs->mem.base),
                ZydisRegisterGetString(rhs->mem.base),
                ZydisRegisterGetString(lhs->mem.index),
                ZydisRegisterGetString(rhs->mem.index),
                (ZyanU32)lhs->mem.scale, (ZyanU32)rhs->mem.scale,
                (unsigned long long)lhs->mem.disp.value, (ZyanU32)lhs->mem.disp.size,
                (unsigned long long)rhs->mem.disp.value, (ZyanU32)rhs->mem.disp.size);
            ok = ZYAN_FALSE;
        }
        {
            ZyanU64 address_lhs = 0, address_rhs = 0;
            const ZyanBool has_lhs = ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(
                &expected->instruction, lhs, TEST_RUNTIME_ADDRESS, &address_lhs));
            const ZyanBool has_rhs = ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(
                &actual->instruction, rhs, TEST_RUNTIME_ADDRESS, &address_rhs));
            if (has_lhs != has_rhs)
            {
                ReportFailure(name, "operand %u changed absolute-address availability",
                    index);
                ok = ZYAN_FALSE;
            }
            else if (has_lhs && (address_lhs != address_rhs))
            {
                ReportFailure(name,
                    "operand %u changed its absolute address from 0x%llX to 0x%llX", index,
                    (unsigned long long)address_lhs, (unsigned long long)address_rhs);
                ok = ZYAN_FALSE;
            }
        }
        break;
    case ZYDIS_OPERAND_TYPE_POINTER:
        if ((lhs->ptr.segment != rhs->ptr.segment) || (lhs->ptr.offset != rhs->ptr.offset))
        {
            ReportFailure(name, "operand %u changed its pointer", index);
            ok = ZYAN_FALSE;
        }
        break;
    case ZYDIS_OPERAND_TYPE_IMMEDIATE:
        if (lhs->imm.value.u != rhs->imm.value.u)
        {
            ReportFailure(name, "operand %u changed its immediate", index);
            ok = ZYAN_FALSE;
        }
        break;
    default:
        ReportFailure(name, "operand %u has an unexpected type %u", index,
            (ZyanU32)lhs->type);
        ok = ZYAN_FALSE;
        break;
    }
    return ok;
}

/**
 * Compares the full decoder state (including implicit operands) of two decodes.
 */
static ZyanBool CompareInstructions(const char* name, const TestInstruction* expected,
    const TestInstruction* actual)
{
    ZyanBool ok = ZYAN_TRUE;
    const ZydisDecodedInstruction* lhs = &expected->instruction;
    const ZydisDecodedInstruction* rhs = &actual->instruction;

    if (lhs->machine_mode != rhs->machine_mode)
    {
        ReportFailure(name, "machine mode changed from %u to %u",
            (ZyanU32)lhs->machine_mode, (ZyanU32)rhs->machine_mode);
        ok = ZYAN_FALSE;
    }
    if (lhs->mnemonic != rhs->mnemonic)
    {
        ReportFailure(name, "mnemonic changed from '%s' to '%s'",
            ZydisMnemonicGetString(lhs->mnemonic), ZydisMnemonicGetString(rhs->mnemonic));
        ok = ZYAN_FALSE;
    }
    if (lhs->encoding != rhs->encoding)
    {
        ReportFailure(name, "encoding changed from %u to %u", (ZyanU32)lhs->encoding,
            (ZyanU32)rhs->encoding);
        ok = ZYAN_FALSE;
    }
    if (rhs->length > lhs->length)
    {
        ReportFailure(name, "re-encoded instruction is longer (%lu > %lu)",
            (unsigned long)rhs->length, (unsigned long)lhs->length);
        ok = ZYAN_FALSE;
    }
    if (lhs->address_width != rhs->address_width)
    {
        ReportFailure(name, "address width changed from %u to %u",
            (ZyanU32)lhs->address_width, (ZyanU32)rhs->address_width);
        ok = ZYAN_FALSE;
    }
    if (lhs->operand_width != rhs->operand_width)
    {
        ReportFailure(name, "operand width changed from %u to %u",
            (ZyanU32)lhs->operand_width, (ZyanU32)rhs->operand_width);
        ok = ZYAN_FALSE;
    }
    if (lhs->operand_count_visible != rhs->operand_count_visible)
    {
        ReportFailure(name, "visible operand count changed from %u to %u",
            (ZyanU32)lhs->operand_count_visible, (ZyanU32)rhs->operand_count_visible);
        ok = ZYAN_FALSE;
    }
    if (lhs->operand_count != rhs->operand_count)
    {
        ReportFailure(name, "operand count (incl. implicit) changed from %u to %u",
            (ZyanU32)lhs->operand_count, (ZyanU32)rhs->operand_count);
        ok = ZYAN_FALSE;
    }
    if (lhs->avx.mask.mode != rhs->avx.mask.mode)
    {
        ReportFailure(name, "mask mode changed from %u to %u",
            (ZyanU32)lhs->avx.mask.mode, (ZyanU32)rhs->avx.mask.mode);
        ok = ZYAN_FALSE;
    }
    if (lhs->avx.mask.reg != rhs->avx.mask.reg)
    {
        ReportFailure(name, "mask register changed from '%s' to '%s'",
            ZydisRegisterGetString(lhs->avx.mask.reg),
            ZydisRegisterGetString(rhs->avx.mask.reg));
        ok = ZYAN_FALSE;
    }
    if (IsZeroingMask(lhs) != IsZeroingMask(rhs))
    {
        ReportFailure(name, "zeroing bit changed from %u to %u",
            (ZyanU32)IsZeroingMask(lhs), (ZyanU32)IsZeroingMask(rhs));
        ok = ZYAN_FALSE;
    }
    if ((lhs->avx.broadcast.mode != rhs->avx.broadcast.mode) ||
        (lhs->avx.broadcast.is_static != rhs->avx.broadcast.is_static))
    {
        ReportFailure(name, "broadcast changed from %u/%u to %u/%u",
            (ZyanU32)lhs->avx.broadcast.mode, (ZyanU32)lhs->avx.broadcast.is_static,
            (ZyanU32)rhs->avx.broadcast.mode, (ZyanU32)rhs->avx.broadcast.is_static);
        ok = ZYAN_FALSE;
    }
    if (lhs->avx.vector_length != rhs->avx.vector_length)
    {
        ReportFailure(name, "vector length changed from %u to %u",
            (ZyanU32)lhs->avx.vector_length, (ZyanU32)rhs->avx.vector_length);
        ok = ZYAN_FALSE;
    }
    if (lhs->avx.rounding.mode != rhs->avx.rounding.mode)
    {
        ReportFailure(name, "rounding mode changed from %u to %u",
            (ZyanU32)lhs->avx.rounding.mode, (ZyanU32)rhs->avx.rounding.mode);
        ok = ZYAN_FALSE;
    }
    if (lhs->avx.has_sae != rhs->avx.has_sae)
    {
        ReportFailure(name, "SAE flag changed from %u to %u",
            (ZyanU32)lhs->avx.has_sae, (ZyanU32)rhs->avx.has_sae);
        ok = ZYAN_FALSE;
    }
    if (GetDisplacementSize(lhs, expected->operands) !=
        GetDisplacementSize(rhs, actual->operands))
    {
        ReportFailure(name, "displacement size changed from %u to %u",
            (ZyanU32)GetDisplacementSize(lhs, expected->operands),
            (ZyanU32)GetDisplacementSize(rhs, actual->operands));
        ok = ZYAN_FALSE;
    }
    if (GetCompressedDispByte(lhs, expected->operands) !=
        GetCompressedDispByte(rhs, actual->operands))
    {
        ReportFailure(name, "compressed displacement byte changed from 0x%02X to 0x%02X",
            (ZyanU32)GetCompressedDispByte(lhs, expected->operands),
            (ZyanU32)GetCompressedDispByte(rhs, actual->operands));
        ok = ZYAN_FALSE;
    }

    const ZyanU8 operand_count = (lhs->operand_count < rhs->operand_count) ?
        lhs->operand_count : rhs->operand_count;
    for (ZyanU8 i = 0; i < operand_count; ++i)
    {
        if (!CompareOperand(name, i, expected, actual))
        {
            ok = ZYAN_FALSE;
        }
    }
    return ok;
}

/* ============================================================================================== */
/* Feature checks                                                                                 */
/* ============================================================================================== */

/**
 * Checks the decoded EVEX features of a valid sample against the fixture.
 */
static ZyanBool CheckEvexFeatures(const char* name, const TestInstruction* decoded,
    const ExpectedEvexFeatures* expected)
{
    ZyanBool ok = ZYAN_TRUE;
    const ZydisDecodedInstruction* instruction = &decoded->instruction;

    if ((instruction->avx.mask.mode != expected->mask_mode) ||
        (instruction->avx.mask.reg != expected->mask_reg))
    {
        ReportFailure(name, "mask is %u/'%s', expected %u/'%s'",
            (ZyanU32)instruction->avx.mask.mode,
            ZydisRegisterGetString(instruction->avx.mask.reg),
            (ZyanU32)expected->mask_mode, ZydisRegisterGetString(expected->mask_reg));
        ok = ZYAN_FALSE;
    }
    if (IsZeroingMask(instruction) != expected->zeroing)
    {
        ReportFailure(name, "zeroing bit is %u, expected %u",
            (ZyanU32)IsZeroingMask(instruction), (ZyanU32)expected->zeroing);
        ok = ZYAN_FALSE;
    }
    if ((instruction->avx.broadcast.mode != expected->broadcast) ||
        (instruction->avx.broadcast.is_static != expected->broadcast_is_static))
    {
        ReportFailure(name, "broadcast is %u/%u, expected %u/%u",
            (ZyanU32)instruction->avx.broadcast.mode,
            (ZyanU32)instruction->avx.broadcast.is_static,
            (ZyanU32)expected->broadcast, (ZyanU32)expected->broadcast_is_static);
        ok = ZYAN_FALSE;
    }
    if (instruction->avx.vector_length != expected->vector_length)
    {
        ReportFailure(name, "vector length is %u, expected %u",
            (ZyanU32)instruction->avx.vector_length, (ZyanU32)expected->vector_length);
        ok = ZYAN_FALSE;
    }
    if ((instruction->avx.rounding.mode != expected->rounding) ||
        (instruction->avx.has_sae != expected->sae))
    {
        ReportFailure(name, "rounding/SAE is %u/%u, expected %u/%u",
            (ZyanU32)instruction->avx.rounding.mode, (ZyanU32)instruction->avx.has_sae,
            (ZyanU32)expected->rounding, (ZyanU32)expected->sae);
        ok = ZYAN_FALSE;
    }
    if ((instruction->operand_count_visible != expected->operand_count_visible) ||
        (instruction->operand_count != expected->operand_count))
    {
        ReportFailure(name, "operand count is %u/%u, expected %u/%u",
            (ZyanU32)instruction->operand_count_visible,
            (ZyanU32)instruction->operand_count,
            (ZyanU32)expected->operand_count_visible, (ZyanU32)expected->operand_count);
        ok = ZYAN_FALSE;
    }
    if (GetDisplacementSize(instruction, decoded->operands) != expected->disp_size)
    {
        ReportFailure(name, "displacement size is %u, expected %u",
            (ZyanU32)GetDisplacementSize(instruction, decoded->operands),
            (ZyanU32)expected->disp_size);
        ok = ZYAN_FALSE;
    }

    ZyanU8 mem_count = 0;
    for (ZyanU8 i = 0; i < instruction->operand_count; ++i)
    {
        if (decoded->operands[i].type == ZYDIS_OPERAND_TYPE_MEMORY)
        {
            ++mem_count;
        }
    }
    const ZyanU8 expected_mem_count = expected->mem_size ? 1 : 0;
    if (mem_count != expected_mem_count)
    {
        char expected_text[16];
        if (expected_mem_count)
        {
            snprintf(expected_text, sizeof(expected_text), "%u",
                (ZyanU32)expected_mem_count);
        }
        else
        {
            snprintf(expected_text, sizeof(expected_text), "none");
        }
        ReportFailure(name, "found %u memory operands, expected %s", (ZyanU32)mem_count,
            expected_text);
        ok = ZYAN_FALSE;
    }
    if (mem_count)
    {
        const ZydisDecodedOperand* operand = FindMemoryOperand(instruction,
            decoded->operands);
        if ((operand->size != expected->mem_size) ||
            (operand->element_size != expected->mem_element_size))
        {
            ReportFailure(name, "memory width is %u/%u, expected %u/%u",
                (ZyanU32)operand->size, (ZyanU32)operand->element_size,
                (ZyanU32)expected->mem_size, (ZyanU32)expected->mem_element_size);
            ok = ZYAN_FALSE;
        }
    }
    return ok;
}

/* ============================================================================================== */
/* Test-case runners                                                                              */
/* ============================================================================================== */

/**
 * Runs a valid sample through the decode/re-encode/format round trip.
 */
static ZyanBool RunValidCase(const ValidCase* test)
{
    ZyanBool ok = ZYAN_TRUE;
    TestInstruction decoded;
    if (!DecodeHexCase(&decoded, test->machine_mode, test->bytes))
    {
        ReportFailure(test->name, "failed to decode the sample");
        return ZYAN_FALSE;
    }

    const char* mnemonic = ZydisMnemonicGetString(decoded.instruction.mnemonic);
    if (!mnemonic || strcmp(mnemonic, test->mnemonic))
    {
        ReportFailure(test->name, "mnemonic is '%s', expected '%s'",
            mnemonic ? mnemonic : "?", test->mnemonic);
        ok = ZYAN_FALSE;
    }
    if (!CheckEvexFeatures(test->name, &decoded, &test->expected))
    {
        ok = ZYAN_FALSE;
    }
    if (!FormatInstruction(&decoded.instruction, decoded.operands,
            ZYDIS_FORMATTER_STYLE_INTEL, decoded.text_intel, sizeof(decoded.text_intel)) ||
        !FormatInstruction(&decoded.instruction, decoded.operands,
            ZYDIS_FORMATTER_STYLE_ATT, decoded.text_att, sizeof(decoded.text_att)))
    {
        ReportFailure(test->name, "failed to format the decoded instruction");
        return ZYAN_FALSE;
    }
    if (strcmp(decoded.text_intel, test->text_intel))
    {
        ReportFailure(test->name, "Intel text is '%s', expected '%s'", decoded.text_intel,
            test->text_intel);
        ok = ZYAN_FALSE;
    }
    if (strcmp(decoded.text_att, test->text_att))
    {
        ReportFailure(test->name, "ATT text is '%s', expected '%s'", decoded.text_att,
            test->text_att);
        ok = ZYAN_FALSE;
    }

    /* Re-encode the decoded instruction. */
    ZydisEncoderRequest request;
    ZyanStatus status = ZydisEncoderDecodedInstructionToEncoderRequest(&decoded.instruction,
        decoded.operands, decoded.instruction.operand_count_visible, &request);
    if (ZYAN_FAILED(status))
    {
        ReportFailure(test->name, "creating the encoder request failed [0x%08X]",
            (ZyanU32)status);
        return ZYAN_FALSE;
    }
    ZyanU8 encoded[256];
    ZyanUSize encoded_length = sizeof(encoded);
    status = ZydisEncoderEncodeInstruction(&request, encoded, &encoded_length);
    if (ZYAN_FAILED(status))
    {
        ReportFailure(test->name, "re-encoding failed [0x%08X]", (ZyanU32)status);
        return ZYAN_FALSE;
    }

    /* The re-encoded bytes must decode to the same instruction semantics. */
    TestInstruction redecoded;
    if (!DecodeBytes(&redecoded, test->machine_mode, encoded, encoded_length))
    {
        ReportFailure(test->name, "failed to decode the re-encoded instruction");
        return ZYAN_FALSE;
    }
    if (!CompareInstructions(test->name, &decoded, &redecoded))
    {
        ok = ZYAN_FALSE;
    }
    if (!FormatInstruction(&redecoded.instruction, redecoded.operands,
            ZYDIS_FORMATTER_STYLE_INTEL, redecoded.text_intel,
            sizeof(redecoded.text_intel)) ||
        !FormatInstruction(&redecoded.instruction, redecoded.operands,
            ZYDIS_FORMATTER_STYLE_ATT, redecoded.text_att, sizeof(redecoded.text_att)))
    {
        ReportFailure(test->name, "failed to format the re-encoded instruction");
        return ZYAN_FALSE;
    }
    if (strcmp(redecoded.text_intel, decoded.text_intel))
    {
        ReportFailure(test->name, "Intel formatting changed from '%s' to '%s'",
            decoded.text_intel, redecoded.text_intel);
        ok = ZYAN_FALSE;
    }
    if (strcmp(redecoded.text_att, decoded.text_att))
    {
        ReportFailure(test->name, "ATT formatting changed from '%s' to '%s'",
            decoded.text_att, redecoded.text_att);
        ok = ZYAN_FALSE;
    }

    /* Re-encoding must be a fixed point. */
    ZydisEncoderRequest request2;
    status = ZydisEncoderDecodedInstructionToEncoderRequest(&redecoded.instruction,
        redecoded.operands, redecoded.instruction.operand_count_visible, &request2);
    if (ZYAN_FAILED(status))
    {
        ReportFailure(test->name, "creating the second encoder request failed [0x%08X]",
            (ZyanU32)status);
        return ZYAN_FALSE;
    }
    ZyanU8 encoded2[256];
    ZyanUSize encoded2_length = sizeof(encoded2);
    status = ZydisEncoderEncodeInstruction(&request2, encoded2, &encoded2_length);
    if (ZYAN_FAILED(status))
    {
        ReportFailure(test->name, "re-encoding failed [0x%08X]", (ZyanU32)status);
        return ZYAN_FALSE;
    }
    if ((encoded2_length != encoded_length) || memcmp(encoded, encoded2, encoded_length))
    {
        ReportFailure(test->name, "re-encoding is not a fixed point");
        ok = ZYAN_FALSE;
    }
    return ok;
}

/**
 * Runs an illegal-combination sample and verifies explicit rejection.
 */
static ZyanBool RunInvalidCase(const InvalidCase* test)
{
    ZyanBool ok = ZYAN_TRUE;
    TestInstruction decoded;
    memset(&decoded, 0, sizeof(decoded));
    decoded.length = ParseHexBytes(test->bytes, decoded.bytes, sizeof(decoded.bytes));
    if (!decoded.length)
    {
        ReportFailure(test->name, "invalid hex sample");
        return ZYAN_FALSE;
    }

    ZydisDecoder decoder;
    if (!InitializeDecoder(&decoder, test->machine_mode))
    {
        ReportFailure(test->name, "failed to initialize the decoder");
        return ZYAN_FALSE;
    }
    const ZyanStatus status = ZydisDecoderDecodeFull(&decoder, decoded.bytes,
        decoded.length, &decoded.instruction, decoded.operands);
    if (ZYAN_SUCCESS(status))
    {
        char text[256];
        if (!FormatInstruction(&decoded.instruction, decoded.operands,
                ZYDIS_FORMATTER_STYLE_INTEL, text, sizeof(text)))
        {
            text[0] = '\0';
        }
        ReportFailure(test->name, "illegal combination was decoded as '%s'", text);
        return ZYAN_FALSE;
    }
    if (status != test->status)
    {
        ReportFailure(test->name, "status is 0x%08X, expected 0x%08X", (ZyanU32)status,
            (ZyanU32)test->status);
        ok = ZYAN_FALSE;
    }

    /* The rejected decode must not leave visible instruction state behind. */
    if ((decoded.instruction.mnemonic != ZYDIS_MNEMONIC_INVALID) ||
        (decoded.instruction.operand_count != 0) ||
        (decoded.instruction.operand_count_visible != 0))
    {
        ReportFailure(test->name, "rejected decode left visible state (mnemonic %u, "
            "operands %u/%u)", (ZyanU32)decoded.instruction.mnemonic,
            (ZyanU32)decoded.instruction.operand_count_visible,
            (ZyanU32)decoded.instruction.operand_count);
        ok = ZYAN_FALSE;
    }

    /* The rejected bytes must not be renderable as an executable instruction. */
    if (!FormatInstruction(&decoded.instruction, decoded.operands,
            ZYDIS_FORMATTER_STYLE_INTEL, decoded.text_intel, sizeof(decoded.text_intel)) ||
        !FormatInstruction(&decoded.instruction, decoded.operands,
            ZYDIS_FORMATTER_STYLE_ATT, decoded.text_att, sizeof(decoded.text_att)))
    {
        ReportFailure(test->name, "formatting the rejected decode failed");
        ok = ZYAN_FALSE;
    }
    else if (strcmp(decoded.text_intel, "invalid") || strcmp(decoded.text_att, "invalid"))
    {
        ReportFailure(test->name, "rejected bytes are rendered as '%s' / '%s'",
            decoded.text_intel, decoded.text_att);
        ok = ZYAN_FALSE;
    }

    /* The rejected decode must not be re-encodable into an executable instruction. */
    ZyanU8 buffer[64];
    memset(buffer, TEST_BUFFER_SENTINEL, sizeof(buffer));
    ZydisEncoderRequest request;
    ZyanBool encoded = ZYAN_FALSE;
    ZyanStatus encode_status = ZydisEncoderDecodedInstructionToEncoderRequest(
        &decoded.instruction, decoded.operands, decoded.instruction.operand_count_visible,
        &request);
    if (ZYAN_SUCCESS(encode_status))
    {
        ZyanUSize length = sizeof(buffer);
        encode_status = ZydisEncoderEncodeInstruction(&request, buffer, &length);
        encoded = ZYAN_SUCCESS(encode_status);
    }
    if (encoded)
    {
        TestInstruction executable;
        char text[256] = { 0 };
        if (DecodeBytes(&executable, test->machine_mode, buffer, sizeof(buffer)))
        {
            FormatInstruction(&executable.instruction, executable.operands,
                ZYDIS_FORMATTER_STYLE_INTEL, text, sizeof(text));
        }
        ReportFailure(test->name, "rejected sample was re-encoded into executable '%s'",
            text);
        ok = ZYAN_FALSE;
    }
    else
    {
        for (ZyanUSize i = 0; i < sizeof(buffer); ++i)
        {
            if (buffer[i] != TEST_BUFFER_SENTINEL)
            {
                ReportFailure(test->name, "failed encode modified the output buffer");
                ok = ZYAN_FALSE;
                break;
            }
        }
    }
    return ok;
}

/**
 * Runs a machine-mode change on the encoder request of a decoded instruction.
 */
static ZyanBool RunModeChangeCase(const ModeChangeCase* test)
{
    TestInstruction decoded;
    if (!DecodeHexCase(&decoded, test->source_mode, test->bytes))
    {
        ReportFailure(test->name, "failed to decode the sample");
        return ZYAN_FALSE;
    }
    ZydisEncoderRequest request;
    ZyanStatus status = ZydisEncoderDecodedInstructionToEncoderRequest(&decoded.instruction,
        decoded.operands, decoded.instruction.operand_count_visible, &request);
    if (ZYAN_FAILED(status))
    {
        ReportFailure(test->name, "creating the encoder request failed [0x%08X]",
            (ZyanU32)status);
        return ZYAN_FALSE;
    }

    request.machine_mode = test->target_mode;
    if (test->clear_size_hints)
    {
        request.operand_size_hint = ZYDIS_OPERAND_SIZE_HINT_NONE;
        request.address_size_hint = ZYDIS_ADDRESS_SIZE_HINT_NONE;
    }

    ZyanU8 buffer[64];
    memset(buffer, TEST_BUFFER_SENTINEL, sizeof(buffer));
    ZyanUSize length = sizeof(buffer);
    status = ZydisEncoderEncodeInstruction(&request, buffer, &length);

    if (!test->expect_accepted)
    {
        if (ZYAN_SUCCESS(status))
        {
            ReportFailure(test->name, "mode change was silently accepted");
            return ZYAN_FALSE;
        }
        for (ZyanUSize i = 0; i < sizeof(buffer); ++i)
        {
            if (buffer[i] != TEST_BUFFER_SENTINEL)
            {
                ReportFailure(test->name,
                    "rejected mode change modified the output buffer");
                return ZYAN_FALSE;
            }
        }
        return ZYAN_TRUE;
    }

    if (ZYAN_FAILED(status))
    {
        ReportFailure(test->name, "mode change was rejected [0x%08X]", (ZyanU32)status);
        return ZYAN_FALSE;
    }

    /* The re-encoded instruction must keep the original operand semantics. */
    TestInstruction reencoded;
    if (!DecodeBytes(&reencoded, test->target_mode, buffer, length))
    {
        ReportFailure(test->name, "failed to decode the re-encoded instruction");
        return ZYAN_FALSE;
    }
    if (!FormatInstruction(&reencoded.instruction, reencoded.operands,
            ZYDIS_FORMATTER_STYLE_INTEL, reencoded.text_intel,
            sizeof(reencoded.text_intel)) ||
        !FormatInstruction(&reencoded.instruction, reencoded.operands,
            ZYDIS_FORMATTER_STYLE_ATT, reencoded.text_att, sizeof(reencoded.text_att)))
    {
        ReportFailure(test->name, "failed to format the re-encoded instruction");
        return ZYAN_FALSE;
    }
    ZyanBool ok = ZYAN_TRUE;
    if (strcmp(reencoded.text_intel, test->text_intel))
    {
        ReportFailure(test->name, "Intel text is '%s', expected '%s'",
            reencoded.text_intel, test->text_intel);
        ok = ZYAN_FALSE;
    }
    if (strcmp(reencoded.text_att, test->text_att))
    {
        ReportFailure(test->name, "ATT text is '%s', expected '%s'", reencoded.text_att,
            test->text_att);
        ok = ZYAN_FALSE;
    }
    return ok;
}

/* ============================================================================================== */
/* Entry point                                                                                    */
/* ============================================================================================== */

int main(void)
{
    if (ZydisGetVersion() != ZYDIS_VERSION)
    {
        fputs("Invalid Zydis version\n", stderr);
        return 1;
    }

    ZyanU32 passed = 0;
    ZyanU32 failed = 0;

    puts("EVEX valid samples (mask/zeroing/broadcast/disp8 round trip):");
    for (ZyanUSize i = 0; i < TEST_ARRAY_SIZE(VALID_CASES); ++i)
    {
        const ZyanBool ok = RunValidCase(&VALID_CASES[i]);
        printf("[%s] %s\n", ok ? "PASSED" : "FAILED", VALID_CASES[i].name);
        if (ok) { ++passed; } else { ++failed; }
    }

    puts("\nEVEX invalid combinations (explicit rejection):");
    for (ZyanUSize i = 0; i < TEST_ARRAY_SIZE(INVALID_CASES); ++i)
    {
        const ZyanBool ok = RunInvalidCase(&INVALID_CASES[i]);
        printf("[%s] %s\n", ok ? "PASSED" : "FAILED", INVALID_CASES[i].name);
        if (ok) { ++passed; } else { ++failed; }
    }

    puts("\nEVEX machine-mode changes (no silent operand rewrite):");
    for (ZyanUSize i = 0; i < TEST_ARRAY_SIZE(MODE_CHANGE_CASES); ++i)
    {
        const ZyanBool ok = RunModeChangeCase(&MODE_CHANGE_CASES[i]);
        printf("[%s] %s\n", ok ? "PASSED" : "FAILED", MODE_CHANGE_CASES[i].name);
        if (ok) { ++passed; } else { ++failed; }
    }

    /* Make sure implicit operands are covered by the valid fixtures. */
    ZyanU32 implicit_fixtures = 0;
    for (ZyanUSize i = 0; i < TEST_ARRAY_SIZE(VALID_CASES); ++i)
    {
        if (VALID_CASES[i].expected.operand_count >
            VALID_CASES[i].expected.operand_count_visible)
        {
            ++implicit_fixtures;
        }
    }
    printf("\nEVEX fixtures with implicit operands: %u\n", implicit_fixtures);
    if (!implicit_fixtures)
    {
        puts("[FAILED] implicit operands are not covered by the valid fixtures");
        ++failed;
    }

    printf("\n%u passed, %u failed\n", passed, failed);
    if (failed)
    {
        puts("SOME TESTS FAILED");
        return 1;
    }
    puts("ALL TESTS PASSED");
    return 0;
}
