# Evidence and Confidence

## Data model

- `Explanation`
  - `confidence`
  - `low_confidence`
  - `low_confidence_reason`
- `EvidenceRef`
  - `evidence_type`
  - `confidence`
  - related instruction/block/import/string/path fields
  - `unsupported_reason`

## Evidence sources (current)

- CFG and edge facts
- stack events and frame signals
- xrefs (code/import/string)
- IR/SSA facts (IR op traces, phi/memory summary)
- user-applied constraints (no_return/indirect_target/etc.)

## Confidence principles

- Confidence is derived from analysis facts, not generated language.
- Unknown indirect targets reduce confidence.
- Unsupported cases are explicit (`unsupported_reason`) instead of fabricated claims.
- Rule-based provider can raise confidence when import semantics and IR facts agree.

## UI behavior

- explanation panel displays confidence and low-confidence warnings
- evidence items are clickable and can jump back to related instruction/block
- unsupported evidence shows explicit warning text
