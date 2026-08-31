# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 4.0.x   | :white_check_mark: |
| < 4.0   | :x:                |

## Reporting a Vulnerability

**DO NOT** open a public GitHub issue for security vulnerabilities.

### Contact

- **Email:** security@rootlabs.fun
- **PGP Key:** Available at https://rootlabs.fun/.well-known/security.txt
- **Response SLA:** Initial acknowledgment within 48 hours

### What to Include

1. Description of the vulnerability
2. Steps to reproduce (PoC preferred)
3. Affected component (crate name, version, commit)
4. Potential impact assessment
5. Suggested fix (if available)

### Process

1. **Report** — Send vulnerability details via secure channel above
2. **Acknowledge** — We confirm receipt within 48 hours
3. **Assess** — Severity rated per CVSS v3.1 + ATOM-specific impact (authority boundary, effect integrity, secret exposure)
4. **Fix** — Patch developed privately; reporter credited (unless anonymity requested)
5. **Disclose** — Coordinated disclosure after fix is released; CVE requested for CVSS ≥ 7.0
6. **Credit** — Reporter listed in SECURITY-ACKNOWLEDGMENTS.md (opt-in)

### Severity Classification

| Severity | ATOM-Specific Criteria | Target Fix Time |
|----------|----------------------|-----------------|
| **CRITICAL** | Authority bypass, secret leak, effect integrity violation, ledger tamper | 24-72 hours |
| **HIGH** | Capability escalation, memory poisoning, checkpoint forgery | 7 days |
| **MEDIUM** | Information disclosure, denial of service, replay attack | 30 days |
| **LOW** | Minor information leak, non-security bug | Next release |

### Scope

In scope:
- All crates in `/crates/`
- Spec schemas and state machines
- Build and release infrastructure
- Dependencies with known vulnerabilities

Out of scope:
- Social engineering
- Physical attacks
- Third-party services (TabiToken, GitHub, etc.)
- Denial of service against development infrastructure

### Bug Bounty

Currently no formal bug bounty program. Critical findings may receive discretionary rewards.

## Security Architecture

ATOM implements defense-in-depth per the Architecture Constitution v4.0:

- **Sovereign Boundary:** Cognition proposes → Authority permits → Reality determines (INV-001)
- **Effect Integrity:** Durable intent before dispatch, commit-time revalidation (INV-004)
- **Secret Isolation:** Brokered handles, never ambient environment (INV-006)
- **Tamper-Evident Ledger:** Hash-chain with checkpoint verification (INV-007)
- **Taint Governance:** Non-launderable context labels (INV-009)

See `spec/security/owasp-crosswalk.yaml` for OWASP Agentic Top 10 mapping.

## Security Contacts

- **Primary:** Crypty Root (crypty@rootlabs.fun)
- **Backup:** security@rootlabs.fun
