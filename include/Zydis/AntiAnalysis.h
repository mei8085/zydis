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
 * Anti-analysis classification.
 *
 * Certain instructions are used as anti-analysis signals: timing instructions
 * (`RDTSC`, `RDPMC`), processor-identification instructions (`CPUID`),
 * descriptor-table reads (`SIDT`, `SGDT`, `SLDT`, `STR`, `SMSW`), I/O-port
 * traps (`IN`, `OUT`), debugger breakpoints (`INT3`) or hypervisor interface
 * instructions (`VMCALL`, `VMRUN`, ...).
 *
 * The classification in this file describes a *successfully decoded*
 * instruction only. It never rejects, rewrites or re-interprets the result of
 * the regular decoder: mnemonics, operands, lengths and status codes stay
 * exactly what the normal decoding path produces. In particular, input that
 * does not decode keeps returning the same status code it returned before and
 * yields no classification.
 *
 * The following rules keep the classification free of false positives:
 * - It is derived exclusively from the *final* decoder result, i.e. the
 *   resolved mnemonic and the decoded encoding. Prefix bytes are never
 *   inspected directly.
 * - Encodings that only *look* like a signal are therefore handled
 *   naturally: `F3 0F 0D C8` decodes to `NOP` (not `PREFETCHW`),
 *   `F3 0F 1E 38` decodes to `NOP` (not `ENDBR64`) and `0F 1E FA` decodes to
 *   `NOP` as well. None of them is classified.
 * - Truncated input is rejected by the regular decoder before the
 *   classification runs. The classification never reads the input buffer on
 *   its own, so it cannot read out of bounds.
 */

#ifndef ZYDIS_ANTIANALYSIS_H
#define ZYDIS_ANTIANALYSIS_H

#include <Zydis/DecoderTypes.h>
#include <Zydis/MetaInfo.h>
#include <Zydis/Status.h>

#if !defined(ZYDIS_DISABLE_DECODER)
#   include <Zydis/Decoder.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================================== */
/* Enums and types                                                                                */
/* ============================================================================================== */

/**
 * @addtogroup antianalysis Anti-analysis classification
 * Functions and types for classifying decoded instructions as anti-analysis signals.
 * @{
 */

/**
 * Defines the `ZydisAntiAnalysisClass` enum.
 *
 * The classification describes whether and why the decoded instruction is an
 * anti-analysis signal.
 */
typedef enum ZydisAntiAnalysisClass_
{
    /**
     * The instruction is not an anti-analysis signal.
     *
     * This is also the classification of an instruction that merely *looks*
     * like a signal because of a prefix combination or an alias encoding, but
     * actually decodes to a different (regular) instruction.
     */
    ZYDIS_ANTIANALYSIS_CLASS_UNRELATED,
    /**
     * The instruction is an anti-analysis signal that is necessarily valid in
     * the current machine mode.
     *
     * These instructions do not depend on an optional CPU feature or on the
     * processor vendor. Their encoding and their architectural meaning are
     * stable in the current mode. They can still fault at runtime (e.g.
     * because of the privilege level, `IOPL` or a disabled MSR), but such a
     * fault does not change the identity of the instruction.
     */
    ZYDIS_ANTIANALYSIS_CLASS_ARCHITECTURAL,
    /**
     * The instruction is an anti-analysis signal that is only valid in the
     * current mode if a specific CPU feature/ISA extension is present.
     *
     * The gating feature is reported in the `isa_ext` field of
     * `ZydisAntiAnalysisInfo`. On processors without that feature the same
     * bytes raise `#UD`.
     */
    ZYDIS_ANTIANALYSIS_CLASS_FEATURE_DEPENDENT,
    /**
     * The instruction is encoded legally, but its semantics (or its
     * availability) depends on the processor/vendor.
     *
     * This covers undocumented and officially undefined opcodes (`SALC`,
     * `UD0`, `UD1`, `INT1`), instructions whose encoding is a
     * backward-compatible `NOP` on processors without the extension (`LZCNT`,
     * `TZCNT`, `PAUSE`, `ENDBR32`, `ENDBR64`), vendor-specific hypervisor
     * instructions and aliases (`VTX`, `SVM`), and instructions whose
     * availability is vendor-specific outside of the mode they were designed
     * for (`SYSCALL`/`SYSRET` in legacy modes, `SYSENTER`/`SYSEXIT`).
     */
    ZYDIS_ANTIANALYSIS_CLASS_PROCESSOR_DEPENDENT,

    /**
     * Maximum value of this enum.
     */
    ZYDIS_ANTIANALYSIS_CLASS_MAX_VALUE = ZYDIS_ANTIANALYSIS_CLASS_PROCESSOR_DEPENDENT,
    /**
     * The minimum number of bits required to represent all values of this enum.
     */
    ZYDIS_ANTIANALYSIS_CLASS_REQUIRED_BITS =
        ZYAN_BITS_TO_REPRESENT(ZYDIS_ANTIANALYSIS_CLASS_MAX_VALUE)
} ZydisAntiAnalysisClass;

/**
 * Defines the `ZydisAntiAnalysisInfo` struct.
 */
typedef struct ZydisAntiAnalysisInfo_
{
    /**
     * The anti-analysis classification of the decoded instruction.
     */
    ZydisAntiAnalysisClass classification;
    /**
     * The ISA extension associated with the classification.
     *
     * For `ZYDIS_ANTIANALYSIS_CLASS_FEATURE_DEPENDENT` this is the feature
     * that gates the instruction. For
     * `ZYDIS_ANTIANALYSIS_CLASS_PROCESSOR_DEPENDENT` this identifies the
     * vendor-specific extension where one applies (e.g. `VTX`, `SVM`). The
     * field is `ZYDIS_ISA_EXT_INVALID` for all other classifications and for
     * signals that have no associated extension.
     */
    ZydisISAExt isa_ext;
    /**
     * The length of the decoded instruction, in bytes.
     *
     * This is a verbatim copy of `ZydisDecodedInstruction.length`; the
     * classification never changes the instruction length.
     */
    ZyanU8 length;
    /**
     * The number of decoded operands.
     *
     * This is a verbatim copy of `ZydisDecodedInstruction.operand_count`; the
     * classification never changes the operands. It is `0` for an instruction
     * decoded in `ZYDIS_DECODER_MODE_MINIMAL` (that mode does not decode
     * operands) and for input that failed to decode.
     */
    ZyanU8 operand_count;
} ZydisAntiAnalysisInfo;

/* ============================================================================================== */
/* Exported functions                                                                             */
/* ============================================================================================== */

/**
 * Classifies an already decoded instruction as an anti-analysis signal.
 *
 * This function only reads the decoded instruction. It never mutates it and
 * never touches the decoded operands, so the original operands and the
 * instruction length remain available to the caller unchanged.
 *
 * Passing a zero-initialized instruction (or an instruction whose mnemonic is
 * not a valid `ZydisMnemonic`) yields
 * `ZYDIS_ANTIANALYSIS_CLASS_UNRELATED`; the function never treats invalid or
 * uninitialized data as a signal.
 *
 * @param   instruction A pointer to the decoded instruction.
 * @param   info        A pointer to the `ZydisAntiAnalysisInfo` struct that
 *                      receives the classification.
 *
 * @return  A zyan status code.
 */
ZYDIS_EXPORT ZyanStatus ZydisClassifyAntiAnalysis(const ZydisDecodedInstruction* instruction,
    ZydisAntiAnalysisInfo* info);

#if !defined(ZYDIS_DISABLE_DECODER)
/**
 * Decodes and classifies the instruction in the given input `buffer`.
 *
 * The decode uses the regular decoding path, so on success the caller receives
 * exactly the same instruction and operands as from `ZydisDecoderDecodeFull`,
 * including their original length. On failure, the exact same status code as
 * the regular decoder is returned (`ZYDIS_STATUS_NO_MORE_DATA` for truncated
 * input, `ZYDIS_STATUS_INSTRUCTION_TOO_LONG`, `ZYDIS_STATUS_ILLEGAL_*`, ...)
 * and the `info` struct is left at `ZYDIS_ANTIANALYSIS_CLASS_UNRELATED` with a
 * zero length; no classification is reported for input that did not decode.
 *
 * The classification itself is performed by `ZydisClassifyAntiAnalysis` on the
 * untouched decode result, so it cannot introduce false positives for prefix
 * combinations or alias encodings and it cannot read beyond the input buffer.
 *
 * This function is not available in `MINIMAL_MODE`.
 *
 * @param   decoder     A pointer to the `ZydisDecoder` instance.
 * @param   buffer      A pointer to the input buffer.
 * @param   length      The length of the input buffer. Note that this can be
 *                      bigger than the actual size of the instruction -- you
 *                      don't have to know the size up front. This length is
 *                      merely used to prevent Zydis from doing out-of-bounds
 *                      reads on your buffer.
 * @param   instruction A pointer to the `ZydisDecodedInstruction` struct
 *                      receiving the details about the decoded instruction.
 * @param   operands    A pointer to an array with `ZYDIS_MAX_OPERAND_COUNT`
 *                      entries that receives the decoded operands. Excess
 *                      entries are zeroed.
 * @param   info        A pointer to the `ZydisAntiAnalysisInfo` struct that
 *                      receives the classification.
 *
 * @return  A zyan status code.
 */
ZYDIS_EXPORT ZyanStatus ZydisDecoderDecodeAntiAnalysis(const ZydisDecoder* decoder,
    const void* buffer, ZyanUSize length, ZydisDecodedInstruction* instruction,
    ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT], ZydisAntiAnalysisInfo* info);
#endif

/**
 * Returns the specified anti-analysis classification string.
 *
 * @param   classification  The anti-analysis classification.
 *
 * @return  The classification string or `ZYAN_NULL`, if an invalid
 *          classification was passed.
 */
ZYDIS_EXPORT const char* ZydisAntiAnalysisClassGetString(
    ZydisAntiAnalysisClass classification);

/** @} */

/* ============================================================================================== */

#ifdef __cplusplus
}
#endif

#endif /* ZYDIS_ANTIANALYSIS_H */
