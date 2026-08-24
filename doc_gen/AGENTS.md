# doc_gen

Security audit reports, format documentation, and architectural decision records.

## STRUCTURE

```
doc_gen/
├── AUDIT_REPORT_era-compact/    # Compact-mode (--compact) audit notes
├── AUDIT_REPORT_era-engine/     # Adversarial audit reports (V1–V5)
├── AUDIT_REPORT_era-index/      # V2.1 index persistence audit
├── AUDIT_REPORT_era-volume/     # Format atomicity audits (v30)
├── V8P2_ITERATION/              # Volume format v8.2 design iterations
│   ├── PRE_PHASE_3/             # Pre-phase design drafts
│   ├── PHASE_1/                 # Initial design docs
│   ├── PHASE_2/                 # Refinement and migration notes
│   └── PHASE_3/                 # Final v8.2 spec and rollout
└── TODO/                        # Pending architectural work
```

## WHERE TO LOOK

| Need | Location |
|------|----------|
| Adversarial audit methodology | `AUDIT_REPORT_era-engine/ADVERSARIAL_AUDIT_V5_REPORT.md` |
| Compact-mode audit notes | `AUDIT_REPORT_era-compact/` |
| Index persistence audit | `AUDIT_REPORT_era-index/` |
| Volume format atomicity | `AUDIT_REPORT_era-volume/` |
| v8.2 pre-phase drafts | `V8P2_ITERATION/PRE_PHASE_3/` |
| v8.2 format design history | `V8P2_ITERATION/` |
| v8.2 final spec / rollout | `V8P2_ITERATION/PHASE_3/` |

## NOTES

- Audit reports are authoritative references for security invariants
- Format changes must update relevant audit reports
