/***************************************************************************************************

  Zyan Disassembler Library (Zydis)

  Original Author : Florian Bernd

 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.

***************************************************************************************************/

/**
 * @file
 *
 * Integration test for the `EVEX` decode/encode/format round trip.
 *
 * The test pins down the reverse-direction semantics of the `EVEX` feature bits that are only
 * indirectly represented in the decoded form:
 *
 * - the write-mask (merging merges into the old destination, zeroing clears the unmasked lanes),
 * - the zeroing `EVEX.z` bit and its dependence on a non-zero `EVEX.aaa`,
 * - the broadcast element width and its interaction with the memory-operand width,
 * - the compressed 8-bit displacement and its tuple-type scaled value,
 * - implicit (non-visible) operands that are part of the semantic comparison,
 * - the addressing meaning that a machine-mode change must not silently rewrite.
 *
 * Every valid sample is decoded, re-encoded from its own decoded form and decoded again. The
 * second decode must be indistinguishable from the first one, including the full operand array
 * (implicit operands included), the mask/broadcast/rounding attributes, the memory width and the
 * formatted text. Invalid samples must fail with the expected status code and must never be
 * presented as an executable instruction.
 *
 * All samples are kept inline on purpose - the test does not depend on external files.
 */

#include <inttypes.h>

#include <Zycore/LibC.h>
#include <Zydis/Zydis.h>

/* ============================================================================================== */
/* Macros                                                                                         */
/* ============================================================================================== */

/* Runtime address used for formatting and absolute-address checks. Keeping it constant makes the
 * rendered text independent of the instruction length. */
#define TEST_RUNTIME_ADDRESS 0x0000000000004000ull
#define TEST_TEXT_SIZE       256

/* Comparison flags */
#define COMPARE_IGNORE_MACHINE_MODE   (1u << 0)
#define COMPARE_IGNORE_ADDRESS_WIDTH  (1u << 1)
#define COMPARE_IGNORE_TEXT           (1u << 2)
#define COMPARE_ALLOW_LONGER          (1u << 3)
/* `operand_width` is the effective operand-size attribute, which is a function of the machine
 * mode for instructions that scale with hidden operands. Across a mode change it may differ even
 * though the explicit/implicit operand widths do not. */
#define COMPARE_IGNORE_OPERAND_WIDTH  (1u << 4)

/* ============================================================================================== */
/* Enums and types                                                                                */
/* ============================================================================================== */

/**
 * A decoded instruction including its source bytes and formatted representation.
 */
typedef struct TestInstruction_
{
    ZyanU8 bytes[ZYDIS_MAX_INSTRUCTION_LENGTH];
    ZyanUSize length;
    ZydisDecodedInstruction instruction;
    ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];
    char text_intel[TEST_TEXT_SIZE];
    char text_att[TEST_TEXT_SIZE];
} TestInstruction;

/**
 * The `EVEX` specific state that has to survive a decode/encode round trip.
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
 * A valid `EVEX` sample with the exact decoded state it has to produce.
 */
typedef struct ValidCase_
{
    const char *name;
    const char *bytes;
    ZydisMachineMode machine_mode;
    const char *mnemonic;
    ExpectedEvexFeatures expected;
    const char *text_intel;
    const char *text_att;
} ValidCase;

/**
 * An invalid `EVEX` sample that has to be rejected with the given status code.
 */
typedef struct InvalidCase_
{
    const char *name;
    const char *bytes;
    ZydisMachineMode machine_mode;
    ZyanStatus status;
} InvalidCase;

/**
 * A sample that is decoded in one machine mode and re-encoded for another one. The encoder may
 * either reject the request or translate it, but it must never silently rewrite the operands.
 */
typedef struct ModeChangeCase_
{
    const char *name;
    const char *bytes;
    ZydisMachineMode source_mode;
    ZydisMachineMode target_mode;
    ZyanBool clear_size_hints;
    ZyanBool expect_accepted;
    const char *text_intel;
    const char *text_att;
} ModeChangeCase;

/* ============================================================================================== */
/* Test data                                                                                      */
/* ============================================================================================== */

/* Decoded state of each fixture was verified against the sample bytes; the strings are the
 * complete Intel/ATT rendering (including mask, zeroing and broadcast decorations). */
static const ValidCase kValidCases[] =
{
    /* Masking modes and the zeroing bit. */
    { "merge-mask-reg", "62F17C4958C0", ZYDIS_MACHINE_MODE_LONG_64, "vaddps",
      { ZYDIS_MASK_MODE_MERGING, ZYDIS_REGISTER_K1, ZYAN_FALSE, ZYDIS_BROADCAST_MODE_NONE,
        ZYAN_FALSE, ZYDIS_ROUNDING_MODE_NONE, ZYAN_FALSE, 512, 0, 0, 4, 4, 0 },
      "vaddps zmm0 {k1}, zmm0, zmm0",
      "vaddps %zmm0, %zmm0, %zmm0 {%k1}" },
    { "zero-mask-reg", "62F17CCB58C0", ZYDIS_MACHINE_MODE_LONG_64, "vaddps",
      { ZYDIS_MASK_MODE_ZEROING, ZYDIS_REGISTER_K3, ZYAN_TRUE, ZYDIS_BROADCAST_MODE_NONE,
        ZYAN_FALSE, ZYDIS_ROUNDING_MODE_NONE, ZYAN_FALSE, 512, 0, 0, 4, 4, 0 },
      "vaddps zmm0 {k3} {z}, zmm0, zmm0",
      "vaddps %zmm0, %zmm0, %zmm0 {%k3} {z}" },

    /* Masking combined with a compressed 8-bit displacement. */
    { "merge-mask-disp8", "62F17C4958407F", ZYDIS_MACHINE_MODE_LONG_64, "vaddps",
      { ZYDIS_MASK_MODE_MERGING, ZYDIS_REGISTER_K1, ZYAN_FALSE, ZYDIS_BROADCAST_MODE_NONE,
        ZYAN_FALSE, ZYDIS_ROUNDING_MODE_NONE, ZYAN_FALSE, 512, 512, 32, 4, 4, 8 },
      "vaddps zmm0 {k1}, zmm0, zmmword ptr ds:[rax+0x1FC0]",
      "vaddpsz %ds:0x1FC0(%rax), %zmm0, %zmm0 {%k1}" },
    { "zero-mask-disp8", "62F17CC958407F", ZYDIS_MACHINE_MODE_LONG_64, "vaddps",
      { ZYDIS_MASK_MODE_ZEROING, ZYDIS_REGISTER_K1, ZYAN_TRUE, ZYDIS_BROADCAST_MODE_NONE,
        ZYAN_FALSE, ZYDIS_ROUNDING_MODE_NONE, ZYAN_FALSE, 512, 512, 32, 4, 4, 8 },
      "vaddps zmm0 {k1} {z}, zmm0, zmmword ptr ds:[rax+0x1FC0]",
      "vaddpsz %ds:0x1FC0(%rax), %zmm0, %zmm0 {%k1} {z}" },

    /* Broadcast element width = memory operand width, combined with zeroing. */
    { "zero-bcast-disp8", "621155BDDB71F8", ZYDIS_MACHINE_MODE_LONG_64, "vpandd",
      { ZYDIS_MASK_MODE_ZEROING, ZYDIS_REGISTER_K5, ZYAN_TRUE, ZYDIS_BROADCAST_MODE_1_TO_8,
        ZYAN_FALSE, ZYDIS_ROUNDING_MODE_NONE, ZYAN_FALSE, 256, 32, 32, 4, 4, 8 },
      "vpandd ymm14 {k5} {z}, ymm5, dword ptr ds:[r9-0x20] {1to8}",
      "vpanddl %ds:-0x20(%r9) {1to8}, %ymm5, %ymm14 {%k5} {z}" },
    { "bcast-disp8", "62F1ED5B58407F", ZYDIS_MACHINE_MODE_LONG_64, "vaddpd",
      { ZYDIS_MASK_MODE_MERGING, ZYDIS_REGISTER_K3, ZYAN_FALSE, ZYDIS_BROADCAST_MODE_1_TO_8,
        ZYAN_FALSE, ZYDIS_ROUNDING_MODE_NONE, ZYAN_FALSE, 512, 64, 64, 4, 4, 8 },
      "vaddpd zmm0 {k3}, zmm2, qword ptr ds:[rax+0x3F8] {1to8}",
      "vaddpdq %ds:0x3F8(%rax) {1to8}, %zmm2, %zmm0 {%k3}" },
    { "bcast-zero-disp8", "62F1EDDB58407F", ZYDIS_MACHINE_MODE_LONG_64, "vaddpd",
      { ZYDIS_MASK_MODE_ZEROING, ZYDIS_REGISTER_K3, ZYAN_TRUE, ZYDIS_BROADCAST_MODE_1_TO_8,
        ZYAN_FALSE, ZYDIS_ROUNDING_MODE_NONE, ZYAN_FALSE, 512, 64, 64, 4, 4, 8 },
      "vaddpd zmm0 {k3} {z}, zmm2, qword ptr ds:[rax+0x3F8] {1to8}",
      "vaddpdq %ds:0x3F8(%rax) {1to8}, %zmm2, %zmm0 {%k3} {z}" },
    { "bcast-128-disp8", "62F17C1958407F", ZYDIS_MACHINE_MODE_LONG_64, "vaddps",
      { ZYDIS_MASK_MODE_MERGING, ZYDIS_REGISTER_K1, ZYAN_FALSE, ZYDIS_BROADCAST_MODE_1_TO_4,
        ZYAN_FALSE, ZYDIS_ROUNDING_MODE_NONE, ZYAN_FALSE, 128, 32, 32, 4, 4, 8 },
      "vaddps xmm0 {k1}, xmm0, dword ptr ds:[rax+0x1FC] {1to4}",
      "vaddpsl %ds:0x1FC(%rax) {1to4}, %xmm0, %xmm0 {%k1}" },
    { "static-bcast-disp8", "62F27D08784810", ZYDIS_MACHINE_MODE_LONG_64, "vpbroadcastb",
      { ZYDIS_MASK_MODE_DISABLED, ZYDIS_REGISTER_K0, ZYAN_FALSE, ZYDIS_BROADCAST_MODE_1_TO_16,
        ZYAN_TRUE, ZYDIS_ROUNDING_MODE_NONE, ZYAN_FALSE, 128, 8, 8, 3, 3, 8 },
      "vpbroadcastb xmm1, byte ptr ds:[rax+0x10]",
      "vpbroadcastbb %ds:0x10(%rax), %xmm1" },

    /* Embedded rounding/SAE keeps the mask intact. */
    { "round-sae-merge", "62F1FD7958C0", ZYDIS_MACHINE_MODE_LONG_64, "vaddpd",
      { ZYDIS_MASK_MODE_MERGING, ZYDIS_REGISTER_K1, ZYAN_FALSE, ZYDIS_BROADCAST_MODE_NONE,
        ZYAN_FALSE, ZYDIS_ROUNDING_MODE_RZ, ZYAN_TRUE, 512, 0, 0, 4, 4, 0 },
      "vaddpd zmm0 {k1}, zmm0, zmm0 {rz-sae}",
      "vaddpd %zmm0 {rz-sae}, %zmm0, %zmm0 {%k1}" },

    /* Implicit (non-visible) operands must be part of the comparison. */
    { "implicit-flags", "62F17C182FC1", ZYDIS_MACHINE_MODE_LONG_64, "vcomiss",
      { ZYDIS_MASK_MODE_DISABLED, ZYDIS_REGISTER_K0, ZYAN_FALSE, ZYDIS_BROADCAST_MODE_NONE,
        ZYAN_FALSE, ZYDIS_ROUNDING_MODE_NONE, ZYAN_TRUE, 128, 0, 0, 2, 3, 0 },
      "vcomiss xmm0, xmm1 {sae}",
      "vcomiss %xmm1 {sae}, %xmm0" },
    { "implicit-bsr", "62F367488FCA03", ZYDIS_MACHINE_MODE_LONG_64, "top4mxbssps",
      { ZYDIS_MASK_MODE_DISABLED, ZYDIS_REGISTER_K0, ZYAN_FALSE, ZYDIS_BROADCAST_MODE_NONE,
        ZYAN_FALSE, ZYDIS_ROUNDING_MODE_NONE, ZYAN_FALSE, 512, 0, 0, 4, 5, 0 },
      "top4mxbssps tmm1, zmm2, zmm3, 0x03",
      "top4mxbssps $0x03, %zmm3, %zmm2, %tmm1" },
    { "implicit-flags-disp8", "62EC7E08F06510", ZYDIS_MACHINE_MODE_LONG_64, "invept",
      { ZYDIS_MASK_MODE_DISABLED, ZYDIS_REGISTER_K0, ZYAN_FALSE, ZYDIS_BROADCAST_MODE_NONE,
        ZYAN_FALSE, ZYDIS_ROUNDING_MODE_NONE, ZYAN_FALSE, 128, 128, 128, 2, 3, 8 },
      "invept r20, xmmword ptr ds:[r21+0x10]",
      "inveptx %ds:0x10(%r21), %r20" },

    /* Addressing forms that have to survive the round trip. */
    { "rip-relative", "62F17C49580510000000", ZYDIS_MACHINE_MODE_LONG_64, "vaddps",
      { ZYDIS_MASK_MODE_MERGING, ZYDIS_REGISTER_K1, ZYAN_FALSE, ZYDIS_BROADCAST_MODE_NONE,
        ZYAN_FALSE, ZYDIS_ROUNDING_MODE_NONE, ZYAN_FALSE, 512, 512, 32, 4, 4, 32 },
      "vaddps zmm0 {k1}, zmm0, zmmword ptr ds:[0x000000000000401A]",
      "vaddpsz %ds:0x000000000000401A, %zmm0, %zmm0 {%k1}" },
    { "masked-store", "62F17C492911", ZYDIS_MACHINE_MODE_LONG_64, "vmovaps",
      { ZYDIS_MASK_MODE_MERGING, ZYDIS_REGISTER_K1, ZYAN_FALSE, ZYDIS_BROADCAST_MODE_NONE,
        ZYAN_FALSE, ZYDIS_ROUNDING_MODE_NONE, ZYAN_FALSE, 512, 512, 32, 3, 3, 0 },
      "vmovaps zmmword ptr ds:[rcx] {k1}, zmm2",
      "vmovapsz %zmm2, %ds:(%rcx) {%k1}" },
    { "gather-vsib", "62F27D49920C90", ZYDIS_MACHINE_MODE_LONG_64, "vgatherdps",
      { ZYDIS_MASK_MODE_MERGING, ZYDIS_REGISTER_K1, ZYAN_FALSE, ZYDIS_BROADCAST_MODE_NONE,
        ZYAN_FALSE, ZYDIS_ROUNDING_MODE_NONE, ZYAN_FALSE, 512, 32, 32, 3, 3, 0 },
      "vgatherdps zmm1 {k1}, dword ptr ds:[rax+zmm2*4]",
      "vgatherdps %ds:(%rax,%zmm2,4), %zmm1 {%k1}" },
    { "narrow-mem-imm", "6223CD4F3A55E34F", ZYDIS_MACHINE_MODE_LONG_64, "vinserti64x4",
      { ZYDIS_MASK_MODE_MERGING, ZYDIS_REGISTER_K7, ZYAN_FALSE, ZYDIS_BROADCAST_MODE_NONE,
        ZYAN_FALSE, ZYDIS_ROUNDING_MODE_NONE, ZYAN_FALSE, 512, 256, 64, 5, 5, 8 },
      "vinserti64x4 zmm26 {k7}, zmm6, ymmword ptr ss:[rbp-0x3A0], 0x4F",
      "vinserti64x4y $0x4F, %ss:-0x3A0(%rbp), %zmm6, %zmm26 {%k7}" },
    { "disp8-32bit", "62F17C4958407F", ZYDIS_MACHINE_MODE_LONG_COMPAT_32, "vaddps",
      { ZYDIS_MASK_MODE_MERGING, ZYDIS_REGISTER_K1, ZYAN_FALSE, ZYDIS_BROADCAST_MODE_NONE,
        ZYAN_FALSE, ZYDIS_ROUNDING_MODE_NONE, ZYAN_FALSE, 512, 512, 32, 4, 4, 8 },
      "vaddps zmm0 {k1}, zmm0, zmmword ptr ds:[eax+0x1FC0]",
      "vaddpsz %ds:0x1FC0(%eax), %zmm0, %zmm0 {%k1}" },
    { "disp8-16bit", "62F17C4958407F", ZYDIS_MACHINE_MODE_LONG_COMPAT_16, "vaddps",
      { ZYDIS_MASK_MODE_MERGING, ZYDIS_REGISTER_K1, ZYAN_FALSE, ZYDIS_BROADCAST_MODE_NONE,
        ZYAN_FALSE, ZYDIS_ROUNDING_MODE_NONE, ZYAN_FALSE, 512, 512, 32, 4, 4, 8 },
      "vaddps zmm0 {k1}, zmm0, zmmword ptr ds:[bx+si*1+0x1FC0]",
      "vaddpsz %ds:0x1FC0(%bx,%si,1), %zmm0, %zmm0 {%k1}" },
    { "absolute-32bit", "62F17C4958042578563412", ZYDIS_MACHINE_MODE_LONG_COMPAT_32, "vaddps",
      { ZYDIS_MASK_MODE_MERGING, ZYDIS_REGISTER_K1, ZYAN_FALSE, ZYDIS_BROADCAST_MODE_NONE,
        ZYAN_FALSE, ZYDIS_ROUNDING_MODE_NONE, ZYAN_FALSE, 512, 512, 32, 4, 4, 32 },
      "vaddps zmm0 {k1}, zmm0, zmmword ptr ds:[0x12345678]",
      "vaddpsz %ds:0x12345678, %zmm0, %zmm0 {%k1}" },
};

static const InvalidCase kInvalidCases[] =
{
    /* `EVEX.z` without a matching non-zero `EVEX.aaa`. */
    { "zeroing-without-mask", "62F17CC858C0", ZYDIS_MACHINE_MODE_LONG_64,
      ZYDIS_STATUS_INVALID_MASK },
    /* Mask required, but `EVEX.aaa == 0`. */
    { "required-mask-missing", "62F17C092FC1", ZYDIS_MACHINE_MODE_LONG_64,
      ZYDIS_STATUS_INVALID_MASK },
    { "gather-mask-missing", "62F27D48920C90", ZYDIS_MACHINE_MODE_LONG_64,
      ZYDIS_STATUS_INVALID_MASK },
    { "scatter-mask-missing", "62F27D48910C90", ZYDIS_MACHINE_MODE_LONG_64,
      ZYDIS_STATUS_INVALID_MASK },
    /* Zeroing is meaningless for a pure store or a mask-destination instruction. */
    { "zeroing-on-store", "62F17CCB2911", ZYDIS_MACHINE_MODE_LONG_64,
      ZYDIS_STATUS_INVALID_MASK },
    { "zeroing-on-mask-destination", "62F17CCBC2C100", ZYDIS_MACHINE_MODE_LONG_64,
      ZYDIS_STATUS_INVALID_MASK },
    /* `EVEX.L'L == 3` is only valid together with embedded rounding/SAE (`EVEX.b == 1`). */
    { "vector-length-3", "62F17C6858C0", ZYDIS_MACHINE_MODE_LONG_64,
      ZYDIS_STATUS_MALFORMED_EVEX },
    /* `EVEX.mmm == 0` is not a valid opcode map. */
    { "invalid-opcode-map", "62F07C4858C0", ZYDIS_MACHINE_MODE_LONG_64,
      ZYDIS_STATUS_INVALID_MAP },
    /* The broadcast bit is not accepted for instructions with static broadcast. */
    { "broadcast-bit-on-static-broadcast", "62F27D18784810", ZYDIS_MACHINE_MODE_LONG_64,
      ZYDIS_STATUS_DECODING_ERROR },
    /* `EVEX.V' == 0` requires 64-bit mode. */
    { "v4-clear-outside-64bit", "62F17C4058C0", ZYDIS_MACHINE_MODE_LONG_COMPAT_32,
      ZYDIS_STATUS_MALFORMED_EVEX },
    /* The encoded register does not match the instruction definition. */
    { "invalid-register", "6276FF4895C3", ZYDIS_MACHINE_MODE_LONG_64,
      ZYDIS_STATUS_BAD_REGISTER },
    /* `EVEX` is not available in 16-bit real mode. */
    { "evex-in-real-16", "62F17C4858C0", ZYDIS_MACHINE_MODE_REAL_16,
      ZYDIS_STATUS_DECODING_ERROR },
    /* Truncated prefixes must not be reported as instructions. */
    { "truncated-evex-4", "62F17C48", ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STATUS_NO_MORE_DATA },
    { "truncated-evex-5", "62F17C4858", ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STATUS_NO_MORE_DATA },
};

static const ModeChangeCase kModeChangeCases[] =
{
    /* Accepted translations: the address size (and thus the base register width) is kept, the
     * encoder only adds/removes the address-size override prefix. */
    { "disp8-32bit-to-64bit", "62F17C4958407F", ZYDIS_MACHINE_MODE_LONG_COMPAT_32,
      ZYDIS_MACHINE_MODE_LONG_64, ZYAN_FALSE, ZYAN_TRUE,
      "vaddps zmm0 {k1}, zmm0, zmmword ptr ds:[eax+0x1FC0]",
      "vaddpsz %ds:0x1FC0(%eax), %zmm0, %zmm0 {%k1}" },
    { "disp8-16bit-to-32bit", "62F17C4958407F", ZYDIS_MACHINE_MODE_LONG_COMPAT_16,
      ZYDIS_MACHINE_MODE_LONG_COMPAT_32, ZYAN_FALSE, ZYAN_TRUE,
      "vaddps zmm0 {k1}, zmm0, zmmword ptr ds:[bx+si*1+0x1FC0]",
      "vaddpsz %ds:0x1FC0(%bx,%si,1), %zmm0, %zmm0 {%k1}" },
    { "disp8-32bit-to-16bit", "62F17C4958407F", ZYDIS_MACHINE_MODE_LONG_COMPAT_32,
      ZYDIS_MACHINE_MODE_LONG_COMPAT_16, ZYAN_FALSE, ZYAN_TRUE,
      "vaddps zmm0 {k1}, zmm0, zmmword ptr ds:[eax+0x1FC0]",
      "vaddpsz %ds:0x1FC0(%eax), %zmm0, %zmm0 {%k1}" },
    { "bcast-zero-32bit-to-64bit", "62F1EDDB58407F", ZYDIS_MACHINE_MODE_LONG_COMPAT_32,
      ZYDIS_MACHINE_MODE_LONG_64, ZYAN_FALSE, ZYAN_TRUE,
      "vaddpd zmm0 {k3} {z}, zmm2, qword ptr ds:[eax+0x3F8] {1to8}",
      "vaddpdq %ds:0x3F8(%eax) {1to8}, %zmm2, %zmm0 {%k3} {z}" },
    { "bcast-128-32bit-to-64bit", "62F17C1958407F", ZYDIS_MACHINE_MODE_LONG_COMPAT_32,
      ZYDIS_MACHINE_MODE_LONG_64, ZYAN_FALSE, ZYAN_TRUE,
      "vaddps xmm0 {k1}, xmm0, dword ptr ds:[eax+0x1FC] {1to4}",
      "vaddpsl %ds:0x1FC(%eax) {1to4}, %xmm0, %xmm0 {%k1}" },
    /* Absolute and EIP-relative addresses keep their meaning; only the rendering width differs. */
    { "absolute-32bit-to-64bit", "62F17C4958042578563412", ZYDIS_MACHINE_MODE_LONG_COMPAT_32,
      ZYDIS_MACHINE_MODE_LONG_64, ZYAN_FALSE, ZYAN_TRUE,
      "vaddps zmm0 {k1}, zmm0, zmmword ptr ds:[0x0000000012345678]",
      "vaddpsz %ds:0x0000000012345678, %zmm0, %zmm0 {%k1}" },
    { "eip-relative-32bit-to-64bit", "62F17C49580510000000", ZYDIS_MACHINE_MODE_LONG_COMPAT_32,
      ZYDIS_MACHINE_MODE_LONG_64, ZYAN_FALSE, ZYAN_TRUE,
      "vaddps zmm0 {k1}, zmm0, zmmword ptr ds:[0x0000000000000010]",
      "vaddpsz %ds:0x0000000000000010, %zmm0, %zmm0 {%k1}" },
    /* Without the propagated size hints the register-only form is accepted even in 32-bit mode
     * and must still encode the same instruction. */
    { "hints-cleared-64bit-to-32bit", "62F17C4958C0", ZYDIS_MACHINE_MODE_LONG_64,
      ZYDIS_MACHINE_MODE_LONG_COMPAT_32, ZYAN_TRUE, ZYAN_TRUE,
      "vaddps zmm0 {k1}, zmm0, zmm0",
      "vaddps %zmm0, %zmm0, %zmm0 {%k1}" },

    /* Rejected translations: the request must fail cleanly instead of emitting bytes. */
    { "reg-form-64bit-to-32bit", "62F17C4958C0", ZYDIS_MACHINE_MODE_LONG_64,
      ZYDIS_MACHINE_MODE_LONG_COMPAT_32, ZYAN_FALSE, ZYAN_FALSE, ZYAN_NULL, ZYAN_NULL },
    { "disp8-64bit-to-32bit", "62F17C4958407F", ZYDIS_MACHINE_MODE_LONG_64,
      ZYDIS_MACHINE_MODE_LONG_COMPAT_32, ZYAN_FALSE, ZYAN_FALSE, ZYAN_NULL, ZYAN_NULL },
    { "rip-relative-64bit-to-32bit", "62F17C49580510000000", ZYDIS_MACHINE_MODE_LONG_64,
      ZYDIS_MACHINE_MODE_LONG_COMPAT_32, ZYAN_FALSE, ZYAN_FALSE, ZYAN_NULL, ZYAN_NULL },
    { "masked-store-64bit-to-32bit", "62F17C492911", ZYDIS_MACHINE_MODE_LONG_64,
      ZYDIS_MACHINE_MODE_LONG_COMPAT_32, ZYAN_FALSE, ZYAN_FALSE, ZYAN_NULL, ZYAN_NULL },
    { "implicit-operand-64bit-to-32bit", "62F17C182FC1", ZYDIS_MACHINE_MODE_LONG_64,
      ZYDIS_MACHINE_MODE_LONG_COMPAT_32, ZYAN_FALSE, ZYAN_FALSE, ZYAN_NULL, ZYAN_NULL },
    { "broadcast-64bit-to-32bit", "62F1EDDB58407F", ZYDIS_MACHINE_MODE_LONG_64,
      ZYDIS_MACHINE_MODE_LONG_COMPAT_32, ZYAN_FALSE, ZYAN_FALSE, ZYAN_NULL, ZYAN_NULL },
    { "gather-64bit-to-32bit", "62F27D49920C90", ZYDIS_MACHINE_MODE_LONG_64,
      ZYDIS_MACHINE_MODE_LONG_COMPAT_32, ZYAN_FALSE, ZYAN_FALSE, ZYAN_NULL, ZYAN_NULL },
};

/* ============================================================================================== */
/* Helper functions                                                                               */
/* ============================================================================================== */

/**
 * Converts a single hexadecimal character to its value.
 */
static ZyanI8 HexDigitValue(char digit)
{
    if ((digit >= '0') && (digit <= '9'))
    {
        return (ZyanI8)(digit - '0');
    }
    if ((digit >= 'a') && (digit <= 'f'))
    {
        return (ZyanI8)(digit - 'a' + 10);
    }
    if ((digit >= 'A') && (digit <= 'F'))
    {
        return (ZyanI8)(digit - 'A' + 10);
    }
    return -1;
}

/**
 * Parses a hexadecimal byte string into a byte buffer.
 *
 * @return The number of parsed bytes or `0` on error.
 */
static ZyanUSize ParseHexBytes(const char *text, ZyanU8 *buffer, ZyanUSize capacity)
{
    ZyanUSize length = 0;
    while (*text)
    {
        const ZyanI8 high = HexDigitValue(text[0]);
        const ZyanI8 low = HexDigitValue(text[1]);
        if ((high < 0) || (low < 0) || (length == capacity))
        {
            return 0;
        }
        buffer[length++] = (ZyanU8)((high << 4) | low);
        text += 2;
    }
    return length;
}

/**
 * Returns the stack width that belongs to the given machine mode.
 */
static ZyanStatus GetStackWidth(ZydisMachineMode machine_mode, ZydisStackWidth *stack_width)
{
    switch (machine_mode)
    {
    case ZYDIS_MACHINE_MODE_LONG_64:
        *stack_width = ZYDIS_STACK_WIDTH_64;
        break;
    case ZYDIS_MACHINE_MODE_LONG_COMPAT_16:
    case ZYDIS_MACHINE_MODE_LEGACY_16:
    case ZYDIS_MACHINE_MODE_REAL_16:
        *stack_width = ZYDIS_STACK_WIDTH_16;
        break;
    case ZYDIS_MACHINE_MODE_LONG_COMPAT_32:
    case ZYDIS_MACHINE_MODE_LEGACY_32:
        *stack_width = ZYDIS_STACK_WIDTH_32;
        break;
    default:
        return ZYAN_STATUS_INVALID_ARGUMENT;
    }
    return ZYAN_STATUS_SUCCESS;
}

/**
 * Initializes a decoder for the given machine mode.
 */
static ZyanBool InitializeDecoder(ZydisDecoder *decoder, ZydisMachineMode machine_mode)
{
    ZydisStackWidth stack_width;
    if (!ZYAN_SUCCESS(GetStackWidth(machine_mode, &stack_width)))
    {
        return ZYAN_FALSE;
    }
    return ZYAN_SUCCESS(ZydisDecoderInit(decoder, machine_mode, stack_width));
}

/**
 * Formats the given instruction in the given style using the test runtime address.
 */
static ZyanBool FormatInstruction(const ZydisDecodedInstruction *instruction,
    const ZydisDecodedOperand *operands, ZydisFormatterStyle style, char *buffer,
    ZyanUSize length)
{
    ZydisFormatter formatter;
    if (!ZYAN_SUCCESS(ZydisFormatterInit(&formatter, style)))
    {
        return ZYAN_FALSE;
    }
    if (!ZYAN_SUCCESS(ZydisFormatterSetProperty(&formatter,
        ZYDIS_FORMATTER_PROP_FORCE_SEGMENT, ZYAN_TRUE)) ||
        !ZYAN_SUCCESS(ZydisFormatterSetProperty(&formatter,
        ZYDIS_FORMATTER_PROP_FORCE_SIZE, ZYAN_TRUE)))
    {
        return ZYAN_FALSE;
    }
    return ZYAN_SUCCESS(ZydisFormatterFormatInstruction(&formatter, instruction, operands,
        instruction->operand_count_visible, buffer, length, TEST_RUNTIME_ADDRESS, ZYAN_NULL));
}

/**
 * Decodes the given bytes and renders both text styles.
 */
static ZyanBool DecodeBytes(TestInstruction *decoded, ZydisMachineMode machine_mode,
    const ZyanU8 *bytes, ZyanUSize length)
{
    ZydisDecoder decoder;
    if (!InitializeDecoder(&decoder, machine_mode))
    {
        return ZYAN_FALSE;
    }

    ZYAN_MEMSET(decoded, 0, sizeof(*decoded));
    ZYAN_MEMCPY(decoded->bytes, bytes, length);
    decoded->length = length;
    if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&decoder, decoded->bytes, decoded->length,
        &decoded->instruction, decoded->operands)))
    {
        return ZYAN_FALSE;
    }

    return FormatInstruction(&decoded->instruction, decoded->operands,
        ZYDIS_FORMATTER_STYLE_INTEL, decoded->text_intel, sizeof(decoded->text_intel)) &&
        FormatInstruction(&decoded->instruction, decoded->operands, ZYDIS_FORMATTER_STYLE_ATT,
        decoded->text_att, sizeof(decoded->text_att));
}

/**
 * Decodes the given fixture in the given machine mode.
 */
static ZyanBool DecodeHexCase(TestInstruction *decoded, ZydisMachineMode machine_mode,
    const char *hex)
{
    ZyanU8 bytes[ZYDIS_MAX_INSTRUCTION_LENGTH];
    const ZyanUSize length = ParseHexBytes(hex, bytes, sizeof(bytes));
    return (length != 0) && DecodeBytes(decoded, machine_mode, bytes, length);
}

/**
 * Renders both text styles of an already decoded instruction and stores them in the test struct.
 */
static ZyanBool FormatDecoded(TestInstruction *decoded)
{
    return FormatInstruction(&decoded->instruction, decoded->operands,
            ZYDIS_FORMATTER_STYLE_INTEL, decoded->text_intel, sizeof(decoded->text_intel)) &&
        FormatInstruction(&decoded->instruction, decoded->operands, ZYDIS_FORMATTER_STYLE_ATT,
            decoded->text_att, sizeof(decoded->text_att));
}

/**
 * Reports a comparison failure and returns `ZYAN_FALSE`.
 */
#define COMPARE_FAIL(...) \
    do \
    { \
        ZYAN_PRINTF("    '%s': ", context); \
        ZYAN_PRINTF(__VA_ARGS__); \
        ZYAN_PRINTF("\n"); \
        return ZYAN_FALSE; \
    } while (0)

/**
 * Compares two decoded instructions, including the complete operand array (implicit operands
 * included) and the `EVEX`-specific attributes.
 *
 * @param   context The test name used in error messages.
 * @param   lhs     The expected/reference instruction.
 * @param   rhs     The re-encoded instruction.
 * @param   flags   A combination of `COMPARE_*` flags.
 *
 * @return `ZYAN_TRUE`, if both instructions are semantically identical.
 */
static ZyanBool CompareInstructions(const char *context, const TestInstruction *lhs,
    const TestInstruction *rhs, ZyanU32 flags)
{
    const ZydisDecodedInstruction *insn1 = &lhs->instruction;
    const ZydisDecodedInstruction *insn2 = &rhs->instruction;

    if (!(flags & COMPARE_IGNORE_MACHINE_MODE) &&
        (insn1->machine_mode != insn2->machine_mode))
    {
        COMPARE_FAIL("machine mode changed from %u to %u",
            (ZyanU32)insn1->machine_mode, (ZyanU32)insn2->machine_mode);
    }
    if (insn1->mnemonic != insn2->mnemonic)
    {
        COMPARE_FAIL("mnemonic changed from '%s' to '%s'",
            ZydisMnemonicGetString(insn1->mnemonic), ZydisMnemonicGetString(insn2->mnemonic));
    }
    if (insn1->encoding != insn2->encoding)
    {
        COMPARE_FAIL("encoding changed from %u to %u",
            (ZyanU32)insn1->encoding, (ZyanU32)insn2->encoding);
    }
    if (!(flags & COMPARE_ALLOW_LONGER) && (rhs->length > lhs->length))
    {
        COMPARE_FAIL("re-encoded instruction is longer (%" PRIu64 " > %" PRIu64 ")",
            (ZyanU64)rhs->length, (ZyanU64)lhs->length);
    }
    if (!(flags & COMPARE_IGNORE_ADDRESS_WIDTH) &&
        (insn1->address_width != insn2->address_width))
    {
        COMPARE_FAIL("address width changed from %u to %u",
            insn1->address_width, insn2->address_width);
    }
    if (!(flags & COMPARE_IGNORE_OPERAND_WIDTH) &&
        (insn1->operand_width != insn2->operand_width))
    {
        COMPARE_FAIL("operand width changed from %u to %u",
            insn1->operand_width, insn2->operand_width);
    }
    if (insn1->operand_count_visible != insn2->operand_count_visible)
    {
        COMPARE_FAIL("visible operand count changed from %u to %u",
            insn1->operand_count_visible, insn2->operand_count_visible);
    }
    /* The total count includes implicit operands - they are part of the semantic comparison. */
    if (insn1->operand_count != insn2->operand_count)
    {
        COMPARE_FAIL("operand count (incl. implicit) changed from %u to %u",
            insn1->operand_count, insn2->operand_count);
    }

    /* Write-mask and zeroing. */
    if (insn1->avx.mask.mode != insn2->avx.mask.mode)
    {
        COMPARE_FAIL("mask mode changed from %u to %u",
            (ZyanU32)insn1->avx.mask.mode, (ZyanU32)insn2->avx.mask.mode);
    }
    if (insn1->avx.mask.reg != insn2->avx.mask.reg)
    {
        COMPARE_FAIL("mask register changed from '%s' to '%s'",
            ZydisRegisterGetString(insn1->avx.mask.reg),
            ZydisRegisterGetString(insn2->avx.mask.reg));
    }
    if (insn1->raw.evex.z != insn2->raw.evex.z)
    {
        COMPARE_FAIL("zeroing bit changed from %u to %u",
            (ZyanU32)insn1->raw.evex.z, (ZyanU32)insn2->raw.evex.z);
    }

    /* Broadcast, vector length and embedded rounding/SAE. */
    if ((insn1->avx.broadcast.mode != insn2->avx.broadcast.mode) ||
        (insn1->avx.broadcast.is_static != insn2->avx.broadcast.is_static))
    {
        COMPARE_FAIL("broadcast changed from %u/%u to %u/%u",
            (ZyanU32)insn1->avx.broadcast.mode, (ZyanU32)insn1->avx.broadcast.is_static,
            (ZyanU32)insn2->avx.broadcast.mode, (ZyanU32)insn2->avx.broadcast.is_static);
    }
    if (insn1->avx.vector_length != insn2->avx.vector_length)
    {
        COMPARE_FAIL("vector length changed from %u to %u",
            (ZyanU32)insn1->avx.vector_length, (ZyanU32)insn2->avx.vector_length);
    }
    if (insn1->avx.rounding.mode != insn2->avx.rounding.mode)
    {
        COMPARE_FAIL("rounding mode changed from %u to %u",
            (ZyanU32)insn1->avx.rounding.mode, (ZyanU32)insn2->avx.rounding.mode);
    }
    if (insn1->avx.has_sae != insn2->avx.has_sae)
    {
        COMPARE_FAIL("SAE flag changed from %u to %u",
            (ZyanU32)insn1->avx.has_sae, (ZyanU32)insn2->avx.has_sae);
    }

    /* Compressed displacement: the physical size must be preserved, and so must the encoded
     * (already scaled) displacement byte. */
    if (insn1->raw.disp.size != insn2->raw.disp.size)
    {
        COMPARE_FAIL("displacement size changed from %u to %u",
            insn1->raw.disp.size, insn2->raw.disp.size);
    }
    if ((insn1->raw.disp.size == 8) && (insn2->raw.disp.size == 8) &&
        (insn1->raw.disp.offset < lhs->length) && (insn2->raw.disp.offset < rhs->length) &&
        (lhs->bytes[insn1->raw.disp.offset] != rhs->bytes[insn2->raw.disp.offset]))
    {
        COMPARE_FAIL("compressed displacement byte changed from 0x%02X to 0x%02X",
            (ZyanU32)lhs->bytes[insn1->raw.disp.offset],
            (ZyanU32)rhs->bytes[insn2->raw.disp.offset]);
    }

    for (ZyanU8 i = 0; i < insn1->operand_count; ++i)
    {
        const ZydisDecodedOperand *op1 = &lhs->operands[i];
        const ZydisDecodedOperand *op2 = &rhs->operands[i];

        if (op1->type != op2->type)
        {
            COMPARE_FAIL("operand %u changed its type from %u to %u",
                (ZyanU32)i, (ZyanU32)op1->type, (ZyanU32)op2->type);
        }
        if (op1->visibility != op2->visibility)
        {
            COMPARE_FAIL("operand %u changed its visibility from %u to %u",
                (ZyanU32)i, (ZyanU32)op1->visibility, (ZyanU32)op2->visibility);
        }
        if (op1->actions != op2->actions)
        {
            COMPARE_FAIL("operand %u changed its actions from 0x%X to 0x%X",
                (ZyanU32)i, (ZyanU32)op1->actions, (ZyanU32)op2->actions);
        }
        /* Logical and element width describe the memory operand width (including broadcasts). */
        if ((op1->size != op2->size) || (op1->element_size != op2->element_size) ||
            (op1->element_count != op2->element_count) ||
            (op1->element_type != op2->element_type))
        {
            COMPARE_FAIL("operand %u changed its width (size %u/%u, element %u/%u, "
                "count %u/%u, type %u/%u)", (ZyanU32)i, (ZyanU32)op1->size, (ZyanU32)op2->size,
                (ZyanU32)op1->element_size,
                (ZyanU32)op2->element_size, (ZyanU32)op1->element_count,
                (ZyanU32)op2->element_count,
                (ZyanU32)op1->element_type, (ZyanU32)op2->element_type);
        }

        switch (op1->type)
        {
        case ZYDIS_OPERAND_TYPE_REGISTER:
            if (op1->reg.value != op2->reg.value)
            {
                COMPARE_FAIL("operand %u changed its register from '%s' to '%s'", (ZyanU32)i,
                    ZydisRegisterGetString(op1->reg.value),
                    ZydisRegisterGetString(op2->reg.value));
            }
            break;
        case ZYDIS_OPERAND_TYPE_MEMORY:
            if ((op1->mem.type != op2->mem.type) || (op1->mem.segment != op2->mem.segment) ||
                (op1->mem.base != op2->mem.base) || (op1->mem.index != op2->mem.index) ||
                (op1->mem.scale != op2->mem.scale) ||
                (op1->mem.disp.value != op2->mem.disp.value) ||
                (op1->mem.disp.size != op2->mem.disp.size))
            {
                COMPARE_FAIL("operand %u changed its addressing (type %u/%u, segment %s/%s, "
                    "base %s/%s, index %s/%s, scale %u/%u, disp 0x%" PRIX64 "/%u vs "
                    "0x%" PRIX64 "/%u)", (ZyanU32)i,
                    (ZyanU32)op1->mem.type, (ZyanU32)op2->mem.type,
                    ZydisRegisterGetString(op1->mem.segment),
                    ZydisRegisterGetString(op2->mem.segment),
                    ZydisRegisterGetString(op1->mem.base),
                    ZydisRegisterGetString(op2->mem.base),
                    ZydisRegisterGetString(op1->mem.index),
                    ZydisRegisterGetString(op2->mem.index),
                    (ZyanU32)op1->mem.scale, (ZyanU32)op2->mem.scale,
                    (ZyanU64)op1->mem.disp.value, (ZyanU32)op1->mem.disp.size,
                    (ZyanU64)op2->mem.disp.value, (ZyanU32)op2->mem.disp.size);
            }
            /* RIP/EIP-relative operands depend on the instruction length, which may legitimately
             * shrink; every other form must resolve to the same absolute address. */
            if ((op1->mem.base != ZYDIS_REGISTER_RIP) &&
                (op1->mem.base != ZYDIS_REGISTER_EIP))
            {
                ZyanU64 address1, address2;
                const ZyanStatus status1 = ZydisCalcAbsoluteAddress(insn1, op1,
                    TEST_RUNTIME_ADDRESS, &address1);
                const ZyanStatus status2 = ZydisCalcAbsoluteAddress(insn2, op2,
                    TEST_RUNTIME_ADDRESS, &address2);
                if (ZYAN_SUCCESS(status1) != ZYAN_SUCCESS(status2))
                {
                    COMPARE_FAIL("operand %u changed absolute-address availability", (ZyanU32)i);
                }
                if (ZYAN_SUCCESS(status1) && (address1 != address2))
                {
                    COMPARE_FAIL("operand %u changed its absolute address from 0x%" PRIX64
                        " to 0x%" PRIX64, (ZyanU32)i, (ZyanU64)address1, (ZyanU64)address2);
                }
            }
            break;
        case ZYDIS_OPERAND_TYPE_POINTER:
            if ((op1->ptr.segment != op2->ptr.segment) ||
                (op1->ptr.offset != op2->ptr.offset))
            {
                COMPARE_FAIL("operand %u changed its pointer", (ZyanU32)i);
            }
            break;
        case ZYDIS_OPERAND_TYPE_IMMEDIATE:
            if ((op1->imm.value.u != op2->imm.value.u) ||
                (op1->imm.is_relative != op2->imm.is_relative) ||
                (op1->imm.is_signed != op2->imm.is_signed))
            {
                COMPARE_FAIL("operand %u changed its immediate", (ZyanU32)i);
            }
            break;
        default:
            COMPARE_FAIL("operand %u has an unexpected type %u", (ZyanU32)i,
                (ZyanU32)op1->type);
        }
    }

    if (!(flags & COMPARE_IGNORE_TEXT))
    {
        if (ZYAN_STRCMP(lhs->text_intel, rhs->text_intel) != 0)
        {
            COMPARE_FAIL("Intel formatting changed from '%s' to '%s'",
                lhs->text_intel, rhs->text_intel);
        }
        if (ZYAN_STRCMP(lhs->text_att, rhs->text_att) != 0)
        {
            COMPARE_FAIL("ATT formatting changed from '%s' to '%s'",
                lhs->text_att, rhs->text_att);
        }
    }

    return ZYAN_TRUE;
}

#undef COMPARE_FAIL

/**
 * Checks the decoded instruction against the expected `EVEX` state of a fixture.
 */
static ZyanBool ValidateExpectedState(const ValidCase *test, const TestInstruction *decoded)
{
    const ZydisDecodedInstruction *insn = &decoded->instruction;
    const ExpectedEvexFeatures *expected = &test->expected;

    if (ZYAN_STRCMP(ZydisMnemonicGetString(insn->mnemonic), test->mnemonic) != 0)
    {
        ZYAN_PRINTF("    '%s': mnemonic is '%s', expected '%s'\n", test->name,
            ZydisMnemonicGetString(insn->mnemonic), test->mnemonic);
        return ZYAN_FALSE;
    }
    if (ZYAN_STRCMP(decoded->text_intel, test->text_intel) != 0)
    {
        ZYAN_PRINTF("    '%s': Intel text is '%s', expected '%s'\n", test->name,
            decoded->text_intel, test->text_intel);
        return ZYAN_FALSE;
    }
    if (ZYAN_STRCMP(decoded->text_att, test->text_att) != 0)
    {
        ZYAN_PRINTF("    '%s': ATT text is '%s', expected '%s'\n", test->name,
            decoded->text_att, test->text_att);
        return ZYAN_FALSE;
    }
    if ((insn->avx.mask.mode != expected->mask_mode) ||
        (insn->avx.mask.reg != expected->mask_reg))
    {
        ZYAN_PRINTF("    '%s': mask is %u/'%s', expected %u/'%s'\n", test->name,
            (ZyanU32)insn->avx.mask.mode, ZydisRegisterGetString(insn->avx.mask.reg),
            (ZyanU32)expected->mask_mode, ZydisRegisterGetString(expected->mask_reg));
        return ZYAN_FALSE;
    }
    if ((insn->raw.evex.z != 0) != expected->zeroing)
    {
        ZYAN_PRINTF("    '%s': zeroing bit is %u, expected %u\n", test->name,
            (ZyanU32)insn->raw.evex.z, (ZyanU32)expected->zeroing);
        return ZYAN_FALSE;
    }
    if ((insn->avx.broadcast.mode != expected->broadcast) ||
        (insn->avx.broadcast.is_static != expected->broadcast_is_static))
    {
        ZYAN_PRINTF("    '%s': broadcast is %u/%u, expected %u/%u\n", test->name,
            (ZyanU32)insn->avx.broadcast.mode, (ZyanU32)insn->avx.broadcast.is_static,
            (ZyanU32)expected->broadcast, (ZyanU32)expected->broadcast_is_static);
        return ZYAN_FALSE;
    }
    if (insn->avx.vector_length != expected->vector_length)
    {
        ZYAN_PRINTF("    '%s': vector length is %u, expected %u\n", test->name,
            (ZyanU32)insn->avx.vector_length, (ZyanU32)expected->vector_length);
        return ZYAN_FALSE;
    }
    if ((insn->avx.rounding.mode != expected->rounding) ||
        (insn->avx.has_sae != expected->sae))
    {
        ZYAN_PRINTF("    '%s': rounding/SAE is %u/%u, expected %u/%u\n", test->name,
            (ZyanU32)insn->avx.rounding.mode, (ZyanU32)insn->avx.has_sae,
            (ZyanU32)expected->rounding, (ZyanU32)expected->sae);
        return ZYAN_FALSE;
    }
    if ((insn->operand_count_visible != expected->operand_count_visible) ||
        (insn->operand_count != expected->operand_count))
    {
        ZYAN_PRINTF("    '%s': operand count is %u/%u, expected %u/%u\n", test->name,
            (ZyanU32)insn->operand_count_visible, (ZyanU32)insn->operand_count,
            (ZyanU32)expected->operand_count_visible, (ZyanU32)expected->operand_count);
        return ZYAN_FALSE;
    }
    if (insn->raw.disp.size != expected->disp_size)
    {
        ZYAN_PRINTF("    '%s': displacement size is %u, expected %u\n", test->name,
            insn->raw.disp.size, expected->disp_size);
        return ZYAN_FALSE;
    }

    /* Memory width and broadcast element width. */
    ZyanU8 memory_operands = 0;
    for (ZyanU8 i = 0; i < insn->operand_count; ++i)
    {
        const ZydisDecodedOperand *operand = &decoded->operands[i];
        if (operand->type != ZYDIS_OPERAND_TYPE_MEMORY)
        {
            continue;
        }
        ++memory_operands;
        if ((operand->size != expected->mem_size) ||
            (operand->element_size != expected->mem_element_size))
        {
            ZYAN_PRINTF("    '%s': memory width is %u/%u, expected %u/%u\n", test->name,
                (ZyanU32)operand->size, (ZyanU32)operand->element_size,
                (ZyanU32)expected->mem_size, (ZyanU32)expected->mem_element_size);
            return ZYAN_FALSE;
        }
    }
    if ((expected->mem_size == 0) != (memory_operands == 0))
    {
        ZYAN_PRINTF("    '%s': found %u memory operands, expected %s\n", test->name,
            (ZyanU32)memory_operands, (expected->mem_size == 0) ? "none" : "one");
        return ZYAN_FALSE;
    }

    return ZYAN_TRUE;
}

/**
 * Runs a single valid fixture through the full decode/encode/format cycle.
 */
static ZyanBool RunValidCase(const ValidCase *test)
{
    TestInstruction source;
    if (!DecodeHexCase(&source, test->machine_mode, test->bytes))
    {
        ZYAN_PRINTF("    '%s': failed to decode the sample\n", test->name);
        return ZYAN_FALSE;
    }
    if (!ValidateExpectedState(test, &source))
    {
        return ZYAN_FALSE;
    }

    ZydisEncoderRequest request;
    ZyanStatus status = ZydisEncoderDecodedInstructionToEncoderRequest(&source.instruction,
        source.operands, source.instruction.operand_count_visible, &request);
    if (!ZYAN_SUCCESS(status))
    {
        ZYAN_PRINTF("    '%s': creating the encoder request failed [0x%08X]\n", test->name,
            status);
        return ZYAN_FALSE;
    }

    TestInstruction reencoded;
    ZYAN_MEMSET(&reencoded, 0, sizeof(reencoded));
    ZyanUSize length = sizeof(reencoded.bytes);
    status = ZydisEncoderEncodeInstruction(&request, reencoded.bytes, &length);
    if (!ZYAN_SUCCESS(status))
    {
        ZYAN_PRINTF("    '%s': re-encoding failed [0x%08X]\n", test->name, status);
        return ZYAN_FALSE;
    }

    ZydisDecoder decoder;
    if (!InitializeDecoder(&decoder, test->machine_mode) ||
        !ZYAN_SUCCESS(ZydisDecoderDecodeFull(&decoder, reencoded.bytes, length,
        &reencoded.instruction, reencoded.operands)))
    {
        ZYAN_PRINTF("    '%s': failed to decode the re-encoded instruction\n", test->name);
        return ZYAN_FALSE;
    }
    reencoded.length = length;
    if (!FormatDecoded(&reencoded))
    {
        ZYAN_PRINTF("    '%s': failed to format the re-encoded instruction\n", test->name);
        return ZYAN_FALSE;
    }

    if (!CompareInstructions(test->name, &source, &reencoded, 0))
    {
        return ZYAN_FALSE;
    }

    /* A second pass has to be a fixed point: the encoder output must be stable. */
    ZydisEncoderRequest request2;
    status = ZydisEncoderDecodedInstructionToEncoderRequest(&reencoded.instruction,
        reencoded.operands, reencoded.instruction.operand_count_visible, &request2);
    if (!ZYAN_SUCCESS(status))
    {
        ZYAN_PRINTF("    '%s': creating the second encoder request failed [0x%08X]\n",
            test->name, status);
        return ZYAN_FALSE;
    }
    ZyanU8 bytes2[ZYDIS_MAX_INSTRUCTION_LENGTH];
    ZyanUSize length2 = sizeof(bytes2);
    status = ZydisEncoderEncodeInstruction(&request2, bytes2, &length2);
    if (!ZYAN_SUCCESS(status) || (length2 != length) ||
        (ZYAN_MEMCMP(bytes2, reencoded.bytes, length) != 0))
    {
        ZYAN_PRINTF("    '%s': re-encoding is not a fixed point\n", test->name);
        return ZYAN_FALSE;
    }

    return ZYAN_TRUE;
}

/**
 * Runs a single invalid fixture: the decoder has to reject it, the result must never be rendered
 * as an executable instruction and the encoder must not turn it into bytes.
 */
static ZyanBool RunInvalidCase(const InvalidCase *test)
{
    ZyanU8 bytes[ZYDIS_MAX_INSTRUCTION_LENGTH];
    const ZyanUSize length = ParseHexBytes(test->bytes, bytes, sizeof(bytes));
    if (length == 0)
    {
        ZYAN_PRINTF("    '%s': invalid hex sample\n", test->name);
        return ZYAN_FALSE;
    }

    ZydisDecoder decoder;
    if (!InitializeDecoder(&decoder, test->machine_mode))
    {
        ZYAN_PRINTF("    '%s': failed to initialize the decoder\n", test->name);
        return ZYAN_FALSE;
    }

    ZydisDecodedInstruction instruction;
    ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];
    ZYAN_MEMSET(&instruction, 0x55, sizeof(instruction));
    ZYAN_MEMSET(operands, 0x55, sizeof(operands));

    const ZyanStatus status = ZydisDecoderDecodeFull(&decoder, bytes, length, &instruction,
        operands);
    if (ZYAN_SUCCESS(status))
    {
        ZYAN_PRINTF("    '%s': illegal combination was decoded as '%s'\n", test->name,
            ZydisMnemonicGetString(instruction.mnemonic));
        return ZYAN_FALSE;
    }
    if (status != test->status)
    {
        ZYAN_PRINTF("    '%s': status is 0x%08X, expected 0x%08X\n", test->name, status,
            test->status);
        return ZYAN_FALSE;
    }
    if ((instruction.mnemonic != ZYDIS_MNEMONIC_INVALID) ||
        (instruction.operand_count != 0) || (instruction.operand_count_visible != 0))
    {
        ZYAN_PRINTF("    '%s': rejected decode left visible state (mnemonic %u, operands %u/%u)\n",
            test->name, (ZyanU32)instruction.mnemonic,
            (ZyanU32)instruction.operand_count_visible, (ZyanU32)instruction.operand_count);
        return ZYAN_FALSE;
    }

    /* The formatter must render the rejected bytes as `invalid`, never as an instruction. */
    char text_intel[TEST_TEXT_SIZE];
    char text_att[TEST_TEXT_SIZE];
    if (!FormatInstruction(&instruction, operands, ZYDIS_FORMATTER_STYLE_INTEL, text_intel,
        sizeof(text_intel)) ||
        !FormatInstruction(&instruction, operands, ZYDIS_FORMATTER_STYLE_ATT, text_att,
        sizeof(text_att)))
    {
        ZYAN_PRINTF("    '%s': formatting the rejected decode failed\n", test->name);
        return ZYAN_FALSE;
    }
    if ((ZYAN_STRCMP(text_intel, "invalid") != 0) || (ZYAN_STRCMP(text_att, "invalid") != 0))
    {
        ZYAN_PRINTF("    '%s': rejected bytes are rendered as '%s' / '%s'\n", test->name,
            text_intel, text_att);
        return ZYAN_FALSE;
    }

    /* The rejected decode must not be convertible into an executable encoding. */
    ZydisEncoderRequest request;
    if (ZYAN_SUCCESS(ZydisEncoderDecodedInstructionToEncoderRequest(&instruction, operands,
        instruction.operand_count_visible, &request)))
    {
        ZyanU8 buffer[ZYDIS_MAX_INSTRUCTION_LENGTH];
        ZYAN_MEMSET(buffer, 0xCC, sizeof(buffer));
        ZyanUSize encoded_length = sizeof(buffer);
        const ZyanStatus encode_status = ZydisEncoderEncodeInstruction(&request, buffer,
            &encoded_length);
        if (ZYAN_SUCCESS(encode_status))
        {
            ZydisDecodedInstruction check;
            ZydisDecodedOperand check_operands[ZYDIS_MAX_OPERAND_COUNT];
            if (ZYAN_SUCCESS(ZydisDecoderDecodeFull(&decoder, buffer, encoded_length, &check,
                check_operands)))
            {
                ZYAN_PRINTF("    '%s': rejected sample was re-encoded into executable '%s'\n",
                    test->name, ZydisMnemonicGetString(check.mnemonic));
                return ZYAN_FALSE;
            }
        }
        else
        {
            /* A failed encode must not touch the caller's buffer. */
            for (ZyanUSize i = 0; i < sizeof(buffer); ++i)
            {
                if (buffer[i] != 0xCC)
                {
                    ZYAN_PRINTF("    '%s': failed encode modified the output buffer\n",
                        test->name);
                    return ZYAN_FALSE;
                }
            }
        }
    }

    return ZYAN_TRUE;
}

/**
 * Runs a single machine-mode change: either an explicit rejection, or a translation that keeps the
 * operand semantics intact.
 */
static ZyanBool RunModeChangeCase(const ModeChangeCase *test)
{
    TestInstruction source;
    if (!DecodeHexCase(&source, test->source_mode, test->bytes))
    {
        ZYAN_PRINTF("    '%s': failed to decode the sample\n", test->name);
        return ZYAN_FALSE;
    }

    ZydisEncoderRequest request;
    ZyanStatus status = ZydisEncoderDecodedInstructionToEncoderRequest(&source.instruction,
        source.operands, source.instruction.operand_count_visible, &request);
    if (!ZYAN_SUCCESS(status))
    {
        ZYAN_PRINTF("    '%s': creating the encoder request failed [0x%08X]\n", test->name,
            status);
        return ZYAN_FALSE;
    }
    request.machine_mode = test->target_mode;
    if (test->clear_size_hints)
    {
        request.address_size_hint = ZYDIS_ADDRESS_SIZE_HINT_NONE;
        request.operand_size_hint = ZYDIS_OPERAND_SIZE_HINT_NONE;
    }

    ZyanU8 buffer[ZYDIS_MAX_INSTRUCTION_LENGTH];
    ZYAN_MEMSET(buffer, 0xCC, sizeof(buffer));
    ZyanUSize length = sizeof(buffer);
    status = ZydisEncoderEncodeInstruction(&request, buffer, &length);

    if (!test->expect_accepted)
    {
        if (ZYAN_SUCCESS(status))
        {
            ZYAN_PRINTF("    '%s': mode change was silently accepted\n", test->name);
            return ZYAN_FALSE;
        }
        for (ZyanUSize i = 0; i < sizeof(buffer); ++i)
        {
            if (buffer[i] != 0xCC)
            {
                ZYAN_PRINTF("    '%s': rejected mode change modified the output buffer\n",
                    test->name);
                return ZYAN_FALSE;
            }
        }
        return ZYAN_TRUE;
    }

    if (!ZYAN_SUCCESS(status))
    {
        ZYAN_PRINTF("    '%s': mode change was rejected [0x%08X]\n", test->name, status);
        return ZYAN_FALSE;
    }

    TestInstruction reencoded;
    ZYAN_MEMSET(&reencoded, 0, sizeof(reencoded));
    ZYAN_MEMCPY(reencoded.bytes, buffer, length);
    reencoded.length = length;
    ZydisDecoder decoder;
    if (!InitializeDecoder(&decoder, test->target_mode) ||
        !ZYAN_SUCCESS(ZydisDecoderDecodeFull(&decoder, reencoded.bytes, reencoded.length,
        &reencoded.instruction, reencoded.operands)))
    {
        ZYAN_PRINTF("    '%s': failed to decode the re-encoded instruction\n", test->name);
        return ZYAN_FALSE;
    }
    if (!FormatDecoded(&reencoded))
    {
        ZYAN_PRINTF("    '%s': failed to format the re-encoded instruction\n", test->name);
        return ZYAN_FALSE;
    }

    /* A mode change may alter the machine/address mode and the rendering width, but it must not
     * change the operands themselves. */
    if (!CompareInstructions(test->name, &source, &reencoded,
        COMPARE_IGNORE_MACHINE_MODE | COMPARE_IGNORE_ADDRESS_WIDTH | COMPARE_IGNORE_TEXT |
        COMPARE_IGNORE_OPERAND_WIDTH | COMPARE_ALLOW_LONGER))
    {
        return ZYAN_FALSE;
    }

    if ((test->text_intel != ZYAN_NULL) &&
        (ZYAN_STRCMP(reencoded.text_intel, test->text_intel) != 0))
    {
        ZYAN_PRINTF("    '%s': Intel text is '%s', expected '%s'\n", test->name,
            reencoded.text_intel, test->text_intel);
        return ZYAN_FALSE;
    }
    if ((test->text_att != ZYAN_NULL) &&
        (ZYAN_STRCMP(reencoded.text_att, test->text_att) != 0))
    {
        ZYAN_PRINTF("    '%s': ATT text is '%s', expected '%s'\n", test->name,
            reencoded.text_att, test->text_att);
        return ZYAN_FALSE;
    }

    return ZYAN_TRUE;
}

/**
 * Counts the valid fixtures that contain at least one implicit operand.
 */
static ZyanU16 CountImplicitOperandFixtures(void)
{
    ZyanU16 count = 0;
    for (ZyanUSize i = 0; i < ZYAN_ARRAY_LENGTH(kValidCases); ++i)
    {
        TestInstruction decoded;
        if (DecodeHexCase(&decoded, kValidCases[i].machine_mode, kValidCases[i].bytes) &&
            (decoded.instruction.operand_count > decoded.instruction.operand_count_visible))
        {
            ++count;
        }
    }
    return count;
}

/* ============================================================================================== */
/* Entry point                                                                                    */
/* ============================================================================================== */

int main(void)
{
    if (ZydisGetVersion() != ZYDIS_VERSION)
    {
        ZYAN_FPRINTF(ZYAN_STDERR, "Invalid Zydis version\n");
        return 1;
    }

    ZyanU16 failures = 0;
    ZyanU16 passed = 0;

    ZYAN_PRINTF("EVEX valid samples (mask/zeroing/broadcast/disp8 round trip):\n");
    for (ZyanUSize i = 0; i < ZYAN_ARRAY_LENGTH(kValidCases); ++i)
    {
        const ZyanBool result = RunValidCase(&kValidCases[i]);
        ZYAN_PRINTF("[%s] %s\n", result ? "PASSED" : "FAILED", kValidCases[i].name);
        result ? ++passed : ++failures;
    }

    ZYAN_PRINTF("\nEVEX invalid combinations (explicit rejection):\n");
    for (ZyanUSize i = 0; i < ZYAN_ARRAY_LENGTH(kInvalidCases); ++i)
    {
        const ZyanBool result = RunInvalidCase(&kInvalidCases[i]);
        ZYAN_PRINTF("[%s] %s\n", result ? "PASSED" : "FAILED", kInvalidCases[i].name);
        result ? ++passed : ++failures;
    }

    ZYAN_PRINTF("\nEVEX machine-mode changes (no silent operand rewrite):\n");
    for (ZyanUSize i = 0; i < ZYAN_ARRAY_LENGTH(kModeChangeCases); ++i)
    {
        const ZyanBool result = RunModeChangeCase(&kModeChangeCases[i]);
        ZYAN_PRINTF("[%s] %s\n", result ? "PASSED" : "FAILED", kModeChangeCases[i].name);
        result ? ++passed : ++failures;
    }

    /* Make sure the implicit-operand fixtures really exercise the implicit comparison. */
    const ZyanU16 implicit_fixtures = CountImplicitOperandFixtures();
    ZYAN_PRINTF("\nEVEX fixtures with implicit operands: %u\n", implicit_fixtures);
    if (implicit_fixtures == 0)
    {
        ZYAN_PRINTF("[FAILED] implicit operands are not covered by the valid fixtures\n");
        ++failures;
    }

    ZYAN_PRINTF("\n%u passed, %u failed\n", passed, failures);
    if (failures != 0)
    {
        ZYAN_PRINTF("SOME TESTS FAILED\n");
        return 1;
    }

    ZYAN_PRINTF("ALL TESTS PASSED\n");
    return 0;
}

/* ============================================================================================== */
