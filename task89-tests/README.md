# Segment-boundary / truncation fuzzy verification

Verifies that x86 instruction **segment boundaries and decode semantics stay consistent under
combinatorial truncation**, in 16-bit, 32-bit and 64-bit modes, with the decoder's read window
physically restricted.

## What it does

For each seed machine-code blob (redundant/duplicated legacy prefixes, two- and three-byte
opcodes, 3DNow!, VEX2/VEX3, XOP, EVEX, MVEX/KNC, SIB + disp16/disp32, imm8/16/32, rel branches,
far pointers, and deliberately un-decodable escapes):

1. A trusted baseline decode is taken on the complete bytes.
2. Every possible read-window length from 1 up to the full instruction length is decoded, plus
   trailing-junk windows, a two-instruction stream and a zero-length window.
3. **Every successful result is checked for**
   - `instruction.length` exactly matching the consumed window and the baseline length;
   - the whole `ZydisDecodedInstruction` struct being byte-identical to the baseline;
   - every prefix byte, displacement and immediate raw value reassembling to the original bytes
     at the reported offset/size;
   - `ZydisGetInstructionSegments()` returning an in-range, contiguous, non-overlapping partition
     whose segments reassemble to the exact original instruction;
   - the full operand array — including read/write `actions` — matching the baseline, and
     `ZydisCalcAbsoluteAddress()` agreeing for every memory operand.
4. **Every failed result is checked for output hygiene**: the instruction struct, operand slots
   and decoder context contain nothing a later consumer could treat as a trusted partial result
   (all zeroed; `mnemonic == INVALID`, `operand_count == 0`, no ModRM/SIB/disp/imm/segment data).

## Restricted read window

Each decode runs through two independent backends:

- **mmap guard page** — bytes end exactly at a `PROT_NONE` page, so any over-read raises
  `SIGSEGV`/`SIGBUS` even without a sanitizer;
- **ASan heap red zone** — bytes live in an exact-sized `malloc`, so over-reads that stay inside
  the same page are caught by AddressSanitizer (UBSan instrumentation is active in both).

`guard_probe.c` and `asan_probe.c` are negative controls proving the two mechanisms actually fire.

## Build / run

```sh
make check     # probes + ASan test + no-sanitizer test + upstream 436-case regression corpus
make all       # ASan segtrunc_test and ZydisInfo
make nosan     # segtrunc_test without sanitizers (mmap guard only)
```

The Makefile is a standalone gcc build (the environment has no cmake); it compiles the in-tree
Zydis and Zycore sources statically.

## Decoder change required by the failure-hygiene requirement

The first run exposed a real defect: mid-decode failures (truncated VEX/EVEX escapes, illegal
LOCK, …) returned through the internal `ZYAN_CHECK` chain leaving a partially populated
`ZydisDecodedInstruction` (consumed `length`, `opcode_map`, ModRM attributes, segment offsets)
and context, which `ZydisGetInstructionSegments()` would turn into fabricated segments.
`src/Decoder.c` now zeroes the output instruction/operand/context structures on every failed
decode at the public API boundary (`ZydisDecoderDecodeFull`, `ZydisDecoderDecodeInstruction`,
`ZydisDecoderDecodeOperands`), including the zero-length `NO_MORE_DATA` path. Successful decode
behavior is unchanged, confirmed by the full upstream regression corpus.
