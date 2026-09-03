# ATOM Governance

**Version:** 4.1.0
**Status:** CANDIDATE_BASELINE

## Architecture Decision Records (ADR)

Architecture decisions follow ADR format:

```markdown
# ADR-XXX: [Title]

Status: proposed | accepted | deprecated | superseded

[Description]

Consequences:
- [Consequence 1]
```

## Normative Precedence

| Priority | Source |
|----------|--------|
| 1 | Architecture Constitution |
| 2 | Canonical machine specification (spec/v4.1/) |
| 3 | ADR records |
| 4 | Acceptance catalog |

## Proposal Process

1. **Draft** — Proposed change documented as ADR
2. **Review** — Security, Architecture Council, Impact Assessment
3. **Approve** — Owner approval required
4. **Implement** — Merge to master
5. **Verify** — Gate evidence recorded

## Breaking Changes

Breaking changes to public API, schema, or CLI require:

- Version bump (semver)
- Migration guide in `spec/v4.1/legacy-disposition.yaml`
- 2+ maintainer approval

## Security Reporting

Private security reports: [cryptyroot-ux/atom SECURITY.md](SECURITY.md)
