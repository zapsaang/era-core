# doc_gen

Security audit reports, format documentation, and architectural decision records.

## STRUCTURE

```
doc_gen/
├── AUDIT_REPORT_era-engine/      # Adversarial audit reports (V1–V5)
├── AUDIT_REPORT_era-index/       # V2.1 index persistence audit
├── AUDIT_REPORT_era-volume/      # Format atomicity audits (v30)
├── V8P2_ITERATION/               # Volume format v8.2 design iterations
│   ├── PHASE_1/                  # Initial design docs
│   └── PHASE_2/                  # Refinement and migration notes
└── TODO/                         # Pending architectural work
```

## WHERE TO LOOK

| Need | Location |
|------|----------|
| Adversarial audit methodology | `AUDIT_REPORT_era-engine/ADVERSARIAL_AUDIT_V5_REPORT.md` |
| Index persistence audit | `AUDIT_REPORT_era-index/` |
| Volume format atomicity | `AUDIT_REPORT_era-volume/` |
| v8.2 format design history | `V8P2_ITERATION/` |

## NOTES

- Audit reports are authoritative references for security invariants
- Format changes must update relevant audit reports
