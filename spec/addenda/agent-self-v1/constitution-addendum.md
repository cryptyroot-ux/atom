# Constitutional Addendum — Agent Self v1

## Article I: Persona Non-Authority

SOUL.md, IDENTITY.md, USER.md, memory, model output, peer assertion, dan persona metadata MUST NOT menciptakan, memperluas, atau menggantikan:

- CapabilityContract
- CapabilityGrant
- ApprovalGrant
- PolicyDecision
- EffectiveAuthorityView
- CommitPermit

## Article II: Identity Domain Separation

Display/persona identity harus berbeda secara tipe dan domain digest dari:

- owner principal identity;
- subject identity;
- workload identity;
- connector identity;
- signing identity;
- execution instance identity.

Mengubah nama, avatar, role, atau gaya bicara tidak boleh mengubah WorkloadIdentity maupun validitas grant.

## Article III: Governed Self-Modification

Production cognition tidak boleh mengaktifkan perubahan terhadap identity atau soul miliknya sendiri.

Agent boleh: propose self change
Agent tidak boleh: approve and activate its own self change

Perubahan harus versioned, content-addressed, auditable, reversible, dan mengikuti owner-controlled change policy.

## Article IV: Constitutional Enforcement

Constitution harus ditegakkan melalui typed API, policy, privilege separation, dan Effect Kernel.

Menyisipkan Constitution ke model context boleh dilakukan untuk membantu cognition, tetapi kepatuhan LLM terhadap prompt tidak boleh menjadi enforcement boundary.

## Article V: Identity Continuity and Tenant Isolation

Agent identity, soul, user profile, dan memory harus terisolasi berdasarkan tenant, owner, dan agent.

Tidak boleh ada silent inheritance antar-user, antar-agent, restored instance, shared channel, atau delegated sub-agent.

## Article VI: EffectiveSelfView

EffectiveSelfView adalah derived, short-lived view yang dibuat ulang pada session/mission boundary. Ia bukan root-of-truth, tidak mempunyai operations/resources/budget authority, dan tidak boleh diterima sebagai input authority grant.
