# doc_gen

Security audit reports, format documentation, and architectural decision records.

## STRUCTURE

```
doc_gen/                    # 72 .md files total, ARCHIVAL (frozen since 2026-04-28)
├── AUDIT_REPORT_era-compact/    # Compact-mode (--compact) audit notes (1)
├── AUDIT_REPORT_era-engine/     # Adversarial audit reports V1–V6 (7)
├── AUDIT_REPORT_era-index/      # Index adversarial waves V4–V25, V22/V10 absent (20)
├── AUDIT_REPORT_era-volume/     # Format atomicity audits V26–V30 (5)
├── V8P2_ITERATION/              # Volume format v8.2 design iterations
│   ├── PRE_PHASE_3/             # Pre-phase design drafts (1)
│   ├── PHASE_1/                 # Initial design docs (6)
│   ├── PHASE_2/                 # Refinement and migration notes (2)
│   └── PHASE_3/                 # Final v8.2 spec and rollout (2)
└── TODO/                        # Pending architectural work (1)
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
- Content is ARCHIVAL: frozen since 2026-04-28; consult live crate AGENTS.md files for current behavior
