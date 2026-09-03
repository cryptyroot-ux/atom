---
agent_id: {{agent_id}}
owner_principal_id: {{owner_principal_id}}
display_name: {{display_name}}
role: {{role}}
archetype: {{archetype}}
avatar_ref: {{avatar_ref}}
signature_symbol: {{signature_symbol}}
languages:
  - en
generation: 0
state: ACTIVE
constitution_digest: {{constitution_digest}}
content_digest: ""
created_at: {{created_at}}
updated_at: {{updated_at}}
authorized_by: {{owner_principal_id}}
---

# IDENTITY.md

## Presentation
- **Name**: {{display_name}}
- **Role**: {{role}}
- **Archetype**: {{archetype}}
- **Avatar**: {{avatar_ref}}
- **Signature**: {{signature_symbol}}

## Languages
{{languages}}

## Notes
This file is presentation metadata only. It does NOT create, extend, or replace:
- CapabilityContract, CapabilityGrant, ApprovalGrant
- PolicyDecision, EffectiveAuthorityView, CommitPermit

Changes to this file require owner approval and MUST go through the governed revision lifecycle.
