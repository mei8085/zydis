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

#include <Zydis/AntiAnalysis.h>
#include <Zydis/DecoderTypes.h>

#if !defined(ZYDIS_DISABLE_DECODER)
#   include <Zydis/Decoder.h>
#endif

/* ============================================================================================== */
/* Macros                                                                                         */
/* ============================================================================================== */

/**
 * The machine-mode bitmap bit for 64-bit mode.
 */
#define ZYDIS_AA_MODE_64    (1u << ZYDIS_MACHINE_MODE_LONG_64)

/* ============================================================================================== */
/* Helpers                                                                                        */
/* ============================================================================================== */

/* ---------------------------------------------------------------------------------------------- */
/* Classification helpers                                                                         */
/* ---------------------------------------------------------------------------------------------- */

/**
 * Builds a classification result for the given (already decoded) instruction.
 *
 * The `length` and `operand_count` fields are copied verbatim from the
 * decoded instruction so that callers always observe the original instruction
 * boundaries, even if they only look at the anti-analysis result.
 */
static void ZydisSetAntiAnalysis(ZydisAntiAnalysisInfo* info,
    const ZydisDecodedInstruction* instruction, ZydisAntiAnalysisClass classification,
    ZydisISAExt isa_ext)
{
    ZYAN_ASSERT(info);
    ZYAN_ASSERT(instruction);

    info->classification = classification;
    info->isa_ext = isa_ext;
    info->length = instruction->length;
    info->operand_count = instruction->operand_count;
}

/**
 * Checks if the decoded instruction runs in one of the given machine modes.
 *
 * @param   instruction A pointer to the `ZydisDecodedInstruction` struct.
 * @param   mode_bitmap A bitmap of `1 << ZydisMachineMode` values.
 *
 * @return  `ZYAN_TRUE` if the current machine mode is contained in the bitmap.
 */
static ZyanBool ZydisAntiAnalysisInMode(const ZydisDecodedInstruction* instruction,
    ZyanU32 mode_bitmap)
{
    ZYAN_ASSERT(instruction);

    /* A caller-supplied instruction struct may carry an out-of-range mode; treat that as
     * "not in the requested mode" instead of performing an out-of-range shift. */
    if ((ZyanU32)instruction->machine_mode > ZYDIS_MACHINE_MODE_MAX_VALUE)
    {
        return ZYAN_FALSE;
    }

    return !!(mode_bitmap & (1u << (ZyanU32)instruction->machine_mode));
}

/* ---------------------------------------------------------------------------------------------- */

/* ============================================================================================== */
/* Classification                                                                                 */
/* ============================================================================================== */

/* ---------------------------------------------------------------------------------------------- */
/* Mnemonic classification                                                                        */
/* ---------------------------------------------------------------------------------------------- */

/**
 * Classifies the instruction by its decoded mnemonic.
 *
 * This function intentionally only inspects stable, semantic fields of the
 * decoded instruction (mnemonic, machine mode and ISA extension). Raw prefix
 * bytes are *not* consulted: a prefix combination that does not change the
 * decoded meaning (e.g. `2E 0F A2` still decoding to `CPUID`, or an ignored
 * `F3` in front of an instruction that has no such prefix form) must not turn
 * a regular instruction into a signal.
 *
 * @param   instruction A pointer to the `ZydisDecodedInstruction` struct.
 * @param   info        A pointer to the `ZydisAntiAnalysisInfo` struct that
 *                      receives the classification.
 */
static void ZydisClassifyMnemonic(const ZydisDecodedInstruction* instruction,
    ZydisAntiAnalysisInfo* info)
{
    ZYAN_ASSERT(instruction);
    ZYAN_ASSERT(info);

    switch (instruction->mnemonic)
    {
    /* ------------------------------------------------------------------------------------------ */
    /* Necessarily valid in the current mode                                                      */
    /* ------------------------------------------------------------------------------------------ */
    /* These instructions are part of the architecture in every machine mode they decode in and
     * their identity does not depend on an optional CPU feature. They can still fault at runtime
     * (privilege level, `IOPL`, disabled/unimplemented MSR), which does not change what they are.
     */
    case ZYDIS_MNEMONIC_CPUID:
    case ZYDIS_MNEMONIC_RDTSC:
    case ZYDIS_MNEMONIC_RDPMC:
    case ZYDIS_MNEMONIC_RDMSR:
    case ZYDIS_MNEMONIC_WRMSR:
    case ZYDIS_MNEMONIC_SIDT:
    case ZYDIS_MNEMONIC_SGDT:
    case ZYDIS_MNEMONIC_SLDT:
    case ZYDIS_MNEMONIC_STR:
    case ZYDIS_MNEMONIC_SMSW:
    case ZYDIS_MNEMONIC_LGDT:
    case ZYDIS_MNEMONIC_LIDT:
    case ZYDIS_MNEMONIC_LLDT:
    case ZYDIS_MNEMONIC_LTR:
    case ZYDIS_MNEMONIC_LMSW:
    case ZYDIS_MNEMONIC_CLTS:
    case ZYDIS_MNEMONIC_IN:
    case ZYDIS_MNEMONIC_OUT:
    case ZYDIS_MNEMONIC_INSB:
    case ZYDIS_MNEMONIC_INSW:
    case ZYDIS_MNEMONIC_INSD:
    case ZYDIS_MNEMONIC_OUTSB:
    case ZYDIS_MNEMONIC_OUTSW:
    case ZYDIS_MNEMONIC_OUTSD:
    case ZYDIS_MNEMONIC_INT:
    case ZYDIS_MNEMONIC_INT3:
    case ZYDIS_MNEMONIC_INTO:
    case ZYDIS_MNEMONIC_UD2:
    case ZYDIS_MNEMONIC_HLT:
    case ZYDIS_MNEMONIC_CLI:
    case ZYDIS_MNEMONIC_STI:
        ZydisSetAntiAnalysis(info, instruction, ZYDIS_ANTIANALYSIS_CLASS_ARCHITECTURAL,
            ZYDIS_ISA_EXT_INVALID);
        return;

    case ZYDIS_MNEMONIC_INT1:
        /* `INT1`/`ICEBP` is an officially undocumented opcode that vendors implement differently
         * (debug trap vs. `#UD`). */
        ZydisSetAntiAnalysis(info, instruction, ZYDIS_ANTIANALYSIS_CLASS_PROCESSOR_DEPENDENT,
            ZYDIS_ISA_EXT_INVALID);
        return;

    case ZYDIS_MNEMONIC_SYSENTER:
    case ZYDIS_MNEMONIC_SYSEXIT:
        /* Optional (CPUID.01H:SEP) rather than base-ISA instructions. They are implemented by the
         * major vendors but are absent on some processor models and are `#UD` outside of the
         * modes they support, so their availability is processor-dependent. */
        ZydisSetAntiAnalysis(info, instruction, ZYDIS_ANTIANALYSIS_CLASS_PROCESSOR_DEPENDENT,
            ZYDIS_ISA_EXT_INVALID);
        return;

    case ZYDIS_MNEMONIC_SYSCALL:
    case ZYDIS_MNEMONIC_SYSRET:
        /* In 64-bit mode `SYSCALL`/`SYSRET` are part of the architecture. In the legacy modes the
         * same opcodes are AMD-only (or `#UD` depending on the vendor and `EFER.SCE`). */
        if (ZydisAntiAnalysisInMode(instruction, ZYDIS_AA_MODE_64))
        {
            ZydisSetAntiAnalysis(info, instruction, ZYDIS_ANTIANALYSIS_CLASS_ARCHITECTURAL,
                ZYDIS_ISA_EXT_INVALID);
        }
        else
        {
            ZydisSetAntiAnalysis(info, instruction,
                ZYDIS_ANTIANALYSIS_CLASS_PROCESSOR_DEPENDENT, ZYDIS_ISA_EXT_INVALID);
        }
        return;

    case ZYDIS_MNEMONIC_SWAPGS:
        /* Only exists in 64-bit mode; the mode itself guarantees the instruction. */
        ZydisSetAntiAnalysis(info, instruction, ZYDIS_ANTIANALYSIS_CLASS_ARCHITECTURAL,
            ZYDIS_ISA_EXT_INVALID);
        return;

    /* ------------------------------------------------------------------------------------------ */
    /* Only valid with a specific CPU feature running (otherwise `#UD`)                           */
    /* ------------------------------------------------------------------------------------------ */
    /* In these cases the encoding is reserved on processors without the feature, so the same bytes
     * do not silently turn into another instruction.
     */
    case ZYDIS_MNEMONIC_RDTSCP:
        ZydisSetAntiAnalysis(info, instruction, ZYDIS_ANTIANALYSIS_CLASS_FEATURE_DEPENDENT,
            ZYDIS_ISA_EXT_RDTSCP);
        return;
    case ZYDIS_MNEMONIC_RDMSRLIST:
    case ZYDIS_MNEMONIC_WRMSRLIST:
        ZydisSetAntiAnalysis(info, instruction, ZYDIS_ANTIANALYSIS_CLASS_FEATURE_DEPENDENT,
            ZYDIS_ISA_EXT_MSRLIST);
        return;
    case ZYDIS_MNEMONIC_URDMSR:
    case ZYDIS_MNEMONIC_UWRMSR:
        ZydisSetAntiAnalysis(info, instruction, ZYDIS_ANTIANALYSIS_CLASS_FEATURE_DEPENDENT,
            ZYDIS_ISA_EXT_USER_MSR);
        return;
    case ZYDIS_MNEMONIC_WRMSRNS:
        ZydisSetAntiAnalysis(info, instruction, ZYDIS_ANTIANALYSIS_CLASS_FEATURE_DEPENDENT,
            ZYDIS_ISA_EXT_WRMSRNS);
        return;
    case ZYDIS_MNEMONIC_RDPID:
        ZydisSetAntiAnalysis(info, instruction, ZYDIS_ANTIANALYSIS_CLASS_FEATURE_DEPENDENT,
            ZYDIS_ISA_EXT_RDPID);
        return;
    case ZYDIS_MNEMONIC_RDPKRU:
    case ZYDIS_MNEMONIC_WRPKRU:
        ZydisSetAntiAnalysis(info, instruction, ZYDIS_ANTIANALYSIS_CLASS_FEATURE_DEPENDENT,
            ZYDIS_ISA_EXT_PKU);
        return;
    case ZYDIS_MNEMONIC_XGETBV:
    case ZYDIS_MNEMONIC_XSETBV:
    case ZYDIS_MNEMONIC_XSAVE:
    case ZYDIS_MNEMONIC_XRSTOR:
        ZydisSetAntiAnalysis(info, instruction, ZYDIS_ANTIANALYSIS_CLASS_FEATURE_DEPENDENT,
            ZYDIS_ISA_EXT_XSAVE);
        return;
    case ZYDIS_MNEMONIC_XSAVEOPT:
        ZydisSetAntiAnalysis(info, instruction, ZYDIS_ANTIANALYSIS_CLASS_FEATURE_DEPENDENT,
            ZYDIS_ISA_EXT_XSAVEOPT);
        return;
    case ZYDIS_MNEMONIC_XSAVEC:
        ZydisSetAntiAnalysis(info, instruction, ZYDIS_ANTIANALYSIS_CLASS_FEATURE_DEPENDENT,
            ZYDIS_ISA_EXT_XSAVEC);
        return;
    case ZYDIS_MNEMONIC_XSAVES:
    case ZYDIS_MNEMONIC_XRSTORS:
        ZydisSetAntiAnalysis(info, instruction, ZYDIS_ANTIANALYSIS_CLASS_FEATURE_DEPENDENT,
            ZYDIS_ISA_EXT_XSAVES);
        return;
    case ZYDIS_MNEMONIC_RDRAND:
        ZydisSetAntiAnalysis(info, instruction, ZYDIS_ANTIANALYSIS_CLASS_FEATURE_DEPENDENT,
            ZYDIS_ISA_EXT_RDRAND);
        return;
    case ZYDIS_MNEMONIC_RDSEED:
        ZydisSetAntiAnalysis(info, instruction, ZYDIS_ANTIANALYSIS_CLASS_FEATURE_DEPENDENT,
            ZYDIS_ISA_EXT_RDSEED);
        return;
    case ZYDIS_MNEMONIC_POPCNT:
        ZydisSetAntiAnalysis(info, instruction, ZYDIS_ANTIANALYSIS_CLASS_FEATURE_DEPENDENT,
            ZYDIS_ISA_EXT_SSE4);
        return;
    case ZYDIS_MNEMONIC_MONITOR:
    case ZYDIS_MNEMONIC_MWAIT:
        ZydisSetAntiAnalysis(info, instruction, ZYDIS_ANTIANALYSIS_CLASS_FEATURE_DEPENDENT,
            ZYDIS_ISA_EXT_MONITOR);
        return;
    case ZYDIS_MNEMONIC_UMONITOR:
    case ZYDIS_MNEMONIC_UMWAIT:
    case ZYDIS_MNEMONIC_TPAUSE:
        ZydisSetAntiAnalysis(info, instruction, ZYDIS_ANTIANALYSIS_CLASS_FEATURE_DEPENDENT,
            ZYDIS_ISA_EXT_WAITPKG);
        return;
    case ZYDIS_MNEMONIC_SERIALIZE:
        ZydisSetAntiAnalysis(info, instruction, ZYDIS_ANTIANALYSIS_CLASS_FEATURE_DEPENDENT,
            ZYDIS_ISA_EXT_SERIALIZE);
        return;
    case ZYDIS_MNEMONIC_CLDEMOTE:
        ZydisSetAntiAnalysis(info, instruction, ZYDIS_ANTIANALYSIS_CLASS_FEATURE_DEPENDENT,
            ZYDIS_ISA_EXT_CLDEMOTE);
        return;
    case ZYDIS_MNEMONIC_CLFLUSHOPT:
        ZydisSetAntiAnalysis(info, instruction, ZYDIS_ANTIANALYSIS_CLASS_FEATURE_DEPENDENT,
            ZYDIS_ISA_EXT_CLFLUSHOPT);
        return;
    case ZYDIS_MNEMONIC_CLWB:
        ZydisSetAntiAnalysis(info, instruction, ZYDIS_ANTIANALYSIS_CLASS_FEATURE_DEPENDENT,
            ZYDIS_ISA_EXT_CLWB);
        return;
    case ZYDIS_MNEMONIC_PBNDKB:
        ZydisSetAntiAnalysis(info, instruction, ZYDIS_ANTIANALYSIS_CLASS_FEATURE_DEPENDENT,
            ZYDIS_ISA_EXT_PBNDKB);
        return;
    case ZYDIS_MNEMONIC_PCONFIG:
        ZydisSetAntiAnalysis(info, instruction, ZYDIS_ANTIANALYSIS_CLASS_FEATURE_DEPENDENT,
            ZYDIS_ISA_EXT_PCONFIG);
        return;
    case ZYDIS_MNEMONIC_PTWRITE:
        ZydisSetAntiAnalysis(info, instruction, ZYDIS_ANTIANALYSIS_CLASS_FEATURE_DEPENDENT,
            ZYDIS_ISA_EXT_PT);
        return;
    case ZYDIS_MNEMONIC_CLRSSBSY:
    case ZYDIS_MNEMONIC_INCSSPD:
    case ZYDIS_MNEMONIC_INCSSPQ:
    case ZYDIS_MNEMONIC_RDSSPD:
    case ZYDIS_MNEMONIC_RDSSPQ:
    case ZYDIS_MNEMONIC_RSTORSSP:
    case ZYDIS_MNEMONIC_SAVEPREVSSP:
    case ZYDIS_MNEMONIC_SETSSBSY:
    case ZYDIS_MNEMONIC_WRSSD:
    case ZYDIS_MNEMONIC_WRSSQ:
    case ZYDIS_MNEMONIC_WRUSSD:
    case ZYDIS_MNEMONIC_WRUSSQ:
        ZydisSetAntiAnalysis(info, instruction, ZYDIS_ANTIANALYSIS_CLASS_FEATURE_DEPENDENT,
            ZYDIS_ISA_EXT_CET);
        return;
    case ZYDIS_MNEMONIC_TESTUI:
    case ZYDIS_MNEMONIC_CLUI:
    case ZYDIS_MNEMONIC_STUI:
    case ZYDIS_MNEMONIC_UIRET:
    case ZYDIS_MNEMONIC_SENDUIPI:
        ZydisSetAntiAnalysis(info, instruction, ZYDIS_ANTIANALYSIS_CLASS_FEATURE_DEPENDENT,
            ZYDIS_ISA_EXT_UINTR);
        return;
    case ZYDIS_MNEMONIC_LKGS:
        ZydisSetAntiAnalysis(info, instruction, ZYDIS_ANTIANALYSIS_CLASS_FEATURE_DEPENDENT,
            ZYDIS_ISA_EXT_LKGS);
        return;
    case ZYDIS_MNEMONIC_ENQCMD:
    case ZYDIS_MNEMONIC_ENQCMDS:
        ZydisSetAntiAnalysis(info, instruction, ZYDIS_ANTIANALYSIS_CLASS_FEATURE_DEPENDENT,
            ZYDIS_ISA_EXT_ENQCMD);
        return;
    case ZYDIS_MNEMONIC_INVPCID:
        ZydisSetAntiAnalysis(info, instruction, ZYDIS_ANTIANALYSIS_CLASS_FEATURE_DEPENDENT,
            ZYDIS_ISA_EXT_INVPCID);
        return;
    case ZYDIS_MNEMONIC_RDFSBASE:
    case ZYDIS_MNEMONIC_RDGSBASE:
    case ZYDIS_MNEMONIC_WRFSBASE:
    case ZYDIS_MNEMONIC_WRGSBASE:
        ZydisSetAntiAnalysis(info, instruction, ZYDIS_ANTIANALYSIS_CLASS_FEATURE_DEPENDENT,
            ZYDIS_ISA_EXT_RDWRFSGS);
        return;
    case ZYDIS_MNEMONIC_GETSEC:
        ZydisSetAntiAnalysis(info, instruction, ZYDIS_ANTIANALYSIS_CLASS_FEATURE_DEPENDENT,
            ZYDIS_ISA_EXT_SMX);
        return;
    case ZYDIS_MNEMONIC_ENCLS:
    case ZYDIS_MNEMONIC_ENCLU:
        ZydisSetAntiAnalysis(info, instruction, ZYDIS_ANTIANALYSIS_CLASS_FEATURE_DEPENDENT,
            ZYDIS_ISA_EXT_SGX);
        return;
    case ZYDIS_MNEMONIC_ENCLV:
        ZydisSetAntiAnalysis(info, instruction, ZYDIS_ANTIANALYSIS_CLASS_FEATURE_DEPENDENT,
            ZYDIS_ISA_EXT_SGX_ENCLV);
        return;

    /* ------------------------------------------------------------------------------------------ */
    /* Legal encoding, processor/vendor-dependent meaning                                         */
    /* ------------------------------------------------------------------------------------------ */
    /* Either the instruction degrades to a different, backward-compatible instruction on
     * processors without the extension (e.g. `LZCNT`/`BSR`, `PAUSE`/`REP NOP`), or the opcode is
     * undocumented/vendor-specific (`SALC`, `UD0`/`UD1`, `VTX`/`SVM`).
     */
    case ZYDIS_MNEMONIC_LZCNT:
        ZydisSetAntiAnalysis(info, instruction, ZYDIS_ANTIANALYSIS_CLASS_PROCESSOR_DEPENDENT,
            ZYDIS_ISA_EXT_LZCNT);
        return;
    case ZYDIS_MNEMONIC_TZCNT:
        ZydisSetAntiAnalysis(info, instruction, ZYDIS_ANTIANALYSIS_CLASS_PROCESSOR_DEPENDENT,
            ZYDIS_ISA_EXT_BMI1);
        return;
    case ZYDIS_MNEMONIC_PAUSE:
        ZydisSetAntiAnalysis(info, instruction, ZYDIS_ANTIANALYSIS_CLASS_PROCESSOR_DEPENDENT,
            ZYDIS_ISA_EXT_PAUSE);
        return;
    case ZYDIS_MNEMONIC_ENDBR32:
    case ZYDIS_MNEMONIC_ENDBR64:
        /* Designed as a `NOP` on processors without CET and only valid in the matching mode. */
        ZydisSetAntiAnalysis(info, instruction, ZYDIS_ANTIANALYSIS_CLASS_PROCESSOR_DEPENDENT,
            ZYDIS_ISA_EXT_CET);
        return;
    case ZYDIS_MNEMONIC_PREFETCH:
    case ZYDIS_MNEMONIC_PREFETCHW:
        /* `0F 0D` is a `NOP` on processors without the prefetch extension, and the `reg` field
         * selects different (vendor-specific) prefetch hints. */
        ZydisSetAntiAnalysis(info, instruction, ZYDIS_ANTIANALYSIS_CLASS_PROCESSOR_DEPENDENT,
            ZYDIS_ISA_EXT_AMD3DNOW_PREFETCH);
        return;
    case ZYDIS_MNEMONIC_PREFETCHWT1:
        ZydisSetAntiAnalysis(info, instruction, ZYDIS_ANTIANALYSIS_CLASS_PROCESSOR_DEPENDENT,
            ZYDIS_ISA_EXT_PREFETCHWT1);
        return;
    case ZYDIS_MNEMONIC_SALC:
        /* Undocumented opcode; executed by some processors, others treat it as invalid. */
        ZydisSetAntiAnalysis(info, instruction, ZYDIS_ANTIANALYSIS_CLASS_PROCESSOR_DEPENDENT,
            ZYDIS_ISA_EXT_INVALID);
        return;
    case ZYDIS_MNEMONIC_UD0:
    case ZYDIS_MNEMONIC_UD1:
        /* Officially undefined encodings; some processors execute them, others raise `#UD`. */
        ZydisSetAntiAnalysis(info, instruction, ZYDIS_ANTIANALYSIS_CLASS_PROCESSOR_DEPENDENT,
            ZYDIS_ISA_EXT_INVALID);
        return;
    case ZYDIS_MNEMONIC_XBEGIN:
    case ZYDIS_MNEMONIC_XEND:
    case ZYDIS_MNEMONIC_XABORT:
    case ZYDIS_MNEMONIC_XTEST:
        /* `RTM` is optional and frequently disabled by microcode. Without it the same bytes
         * either fall back to the abort target immediately, degrade to a flag-setting `NOP`
         * (`XTEST` sets `ZF`) or raise `#UD`, depending on the processor. */
        ZydisSetAntiAnalysis(info, instruction, ZYDIS_ANTIANALYSIS_CLASS_PROCESSOR_DEPENDENT,
            ZYDIS_ISA_EXT_RTM);
        return;
    case ZYDIS_MNEMONIC_CLZERO:
        /* AMD-only; `#UD` on processors without `CLZERO`. */
        ZydisSetAntiAnalysis(info, instruction, ZYDIS_ANTIANALYSIS_CLASS_PROCESSOR_DEPENDENT,
            ZYDIS_ISA_EXT_CLZERO);
        return;
    case ZYDIS_MNEMONIC_MONITORX:
    case ZYDIS_MNEMONIC_MWAITX:
        /* AMD-only. */
        ZydisSetAntiAnalysis(info, instruction, ZYDIS_ANTIANALYSIS_CLASS_PROCESSOR_DEPENDENT,
            ZYDIS_ISA_EXT_MONITORX);
        return;
    case ZYDIS_MNEMONIC_RDPRU:
        /* AMD-only. */
        ZydisSetAntiAnalysis(info, instruction, ZYDIS_ANTIANALYSIS_CLASS_PROCESSOR_DEPENDENT,
            ZYDIS_ISA_EXT_RDPRU);
        return;
    case ZYDIS_MNEMONIC_INVLPGB:
    case ZYDIS_MNEMONIC_TLBSYNC:
        /* AMD-only. */
        ZydisSetAntiAnalysis(info, instruction, ZYDIS_ANTIANALYSIS_CLASS_PROCESSOR_DEPENDENT,
            ZYDIS_ISA_EXT_AMD_INVLPGB);
        return;
    case ZYDIS_MNEMONIC_MCOMMIT:
        /* AMD-only. */
        ZydisSetAntiAnalysis(info, instruction, ZYDIS_ANTIANALYSIS_CLASS_PROCESSOR_DEPENDENT,
            ZYDIS_ISA_EXT_MCOMMIT);
        return;
    case ZYDIS_MNEMONIC_VMCALL:
    case ZYDIS_MNEMONIC_VMLAUNCH:
    case ZYDIS_MNEMONIC_VMRESUME:
    case ZYDIS_MNEMONIC_VMXON:
    case ZYDIS_MNEMONIC_VMXOFF:
    case ZYDIS_MNEMONIC_VMPTRLD:
    case ZYDIS_MNEMONIC_VMPTRST:
    case ZYDIS_MNEMONIC_VMCLEAR:
    case ZYDIS_MNEMONIC_VMREAD:
    case ZYDIS_MNEMONIC_VMWRITE:
    case ZYDIS_MNEMONIC_INVEPT:
    case ZYDIS_MNEMONIC_INVVPID:
        /* Intel `VTX` hypervisor instructions; not implemented on AMD processors. */
        ZydisSetAntiAnalysis(info, instruction, ZYDIS_ANTIANALYSIS_CLASS_PROCESSOR_DEPENDENT,
            ZYDIS_ISA_EXT_VTX);
        return;
    case ZYDIS_MNEMONIC_VMRUN:
    case ZYDIS_MNEMONIC_VMMCALL:
    case ZYDIS_MNEMONIC_VMLOAD:
    case ZYDIS_MNEMONIC_VMSAVE:
    case ZYDIS_MNEMONIC_STGI:
    case ZYDIS_MNEMONIC_CLGI:
    case ZYDIS_MNEMONIC_SKINIT:
    case ZYDIS_MNEMONIC_INVLPGA:
        /* AMD `SVM` hypervisor instructions. `VMMCALL` in particular is an alias of the Intel
         * `VMCALL` opcode; which of the two a processor implements is vendor-specific. */
        ZydisSetAntiAnalysis(info, instruction, ZYDIS_ANTIANALYSIS_CLASS_PROCESSOR_DEPENDENT,
            ZYDIS_ISA_EXT_SVM);
        return;
    case ZYDIS_MNEMONIC_VMFUNC:
        /* AMD `SVM` extension; the same function selector opcodes are `#UD` on Intel. */
        ZydisSetAntiAnalysis(info, instruction, ZYDIS_ANTIANALYSIS_CLASS_PROCESSOR_DEPENDENT,
            ZYDIS_ISA_EXT_VMFUNC);
        return;

    default:
        break;
    }
}

/* ---------------------------------------------------------------------------------------------- */

/* ============================================================================================== */
/* Exported functions                                                                             */
/* ============================================================================================== */

ZyanStatus ZydisClassifyAntiAnalysis(const ZydisDecodedInstruction* instruction,
    ZydisAntiAnalysisInfo* info)
{
    if (!instruction || !info)
    {
        return ZYAN_STATUS_INVALID_ARGUMENT;
    }

    info->classification = ZYDIS_ANTIANALYSIS_CLASS_UNRELATED;
    info->isa_ext = ZYDIS_ISA_EXT_INVALID;
    info->length = instruction->length;
    info->operand_count = instruction->operand_count;

    if ((instruction->mnemonic <= ZYDIS_MNEMONIC_INVALID) ||
        (instruction->mnemonic > ZYDIS_MNEMONIC_MAX_VALUE))
    {
        /* An invalid/uninitialized instruction is never a signal. Keep the length and operand
         * count as-is (both are typically zero for such an instruction). */
        return ZYAN_STATUS_SUCCESS;
    }

    ZydisClassifyMnemonic(instruction, info);
    return ZYAN_STATUS_SUCCESS;
}

#if !defined(ZYDIS_DISABLE_DECODER)
ZyanStatus ZydisDecoderDecodeAntiAnalysis(const ZydisDecoder* decoder,
    const void* buffer, ZyanUSize length, ZydisDecodedInstruction* instruction,
    ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT], ZydisAntiAnalysisInfo* info)
{
    if (!info)
    {
        return ZYAN_STATUS_INVALID_ARGUMENT;
    }

    /* Leave no stale classification behind if the decode fails. */
    info->classification = ZYDIS_ANTIANALYSIS_CLASS_UNRELATED;
    info->isa_ext = ZYDIS_ISA_EXT_INVALID;
    info->length = 0;
    info->operand_count = 0;

    /* The regular decode path is the single source of truth for the status code, the mnemonic,
     * the operands and the instruction length. The classification only consumes its result. */
    ZYAN_CHECK(ZydisDecoderDecodeFull(decoder, buffer, length, instruction, operands));

    return ZydisClassifyAntiAnalysis(instruction, info);
}
#endif

const char* ZydisAntiAnalysisClassGetString(ZydisAntiAnalysisClass classification)
{
    static const char* strings[] =
    {
        "UNRELATED",
        "ARCHITECTURAL",
        "FEATURE_DEPENDENT",
        "PROCESSOR_DEPENDENT"
    };
    ZYAN_STATIC_ASSERT(ZYAN_ARRAY_LENGTH(strings) == ZYDIS_ANTIANALYSIS_CLASS_MAX_VALUE + 1);

    if ((ZyanUSize)classification >= ZYAN_ARRAY_LENGTH(strings))
    {
        return ZYAN_NULL;
    }
    return strings[classification];
}

/* ============================================================================================== */
