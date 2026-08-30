# TASK — atom-kernel (Claude Code · Architect/Reviewer)

Branch: `feat/kernel` · Crate: `crates/atom-kernel`

## Requirement (spec/ AUTHORITATIVE — precedence 1)
- **KRN-001** (P0): ALL consequential mutation paths MUST traverse typed **capability authorization** AND **Effect Kernel commit revalidation**.
- Verification: architecture path test + **adversarial bypass suite**.

## Peran
Kamu Architect. Ini crate PALING kritis — kernel yang menyatukan capability + effect jadi satu jalur mutasi yang tidak bisa di-bypass. Semua crate G1-G4 (capability, effect, privd, approval) bertemu di sini.

## Hard invariants
- Kernel = SATU pintu untuk semua mutasi konsekuensial. Tidak ada jalan pintas.
- Setiap mutasi WAJIB: (1) cek CapabilityGrant valid (atom-capability), (2) revalidasi CommitPermit di titik commit (atom-effect). Dua-duanya, urut.
- Adversarial: mutasi tanpa grant → tolak. Grant valid tapi tanpa permit → tolak. Permit stale/replay → tolak.
- Deny-by-default. Tidak ada `pub` API yang mutasi tanpa lewat gate ini.

## TDD (tulis test dulu — RED → GREEN)
- **Architecture path test**: mutasi sukses HANYA jika grant+permit dua-duanya valid & urut.
- **Adversarial bypass suite**: coba semua jalur pintas (no grant / no permit / stale permit / grant-tapi-beda-resource) → SEMUA ditolak.
- Property: tidak ada input yang bisa commit mutasi tanpa melewati gate ganda.

## Dependency (semua sudah di master)
- `atom-capability` (grant subset lattice)
- `atom-effect` (CommitPermit, EffectIntent, revalidation)
- `atom-privd` (kalau butuh host op), `atom-approval` (kalau butuh approval gate)
- BACA API mereka dulu (grep pub fn) sebelum pakai. Jangan invent nama.

## Larangan
- JANGAN bikin jalur mutasi yang lewat gate. JANGAN merge ke master.
- Commit hanya di feat/kernel, hanya crates/atom-kernel + Cargo.lock.

## Definition of Done
- `cargo test -p atom-kernel` hijau, `cargo clippy` bersih.
- Bypass suite membuktikan TIDAK ada jalur mutasi tanpa grant+permit.
- Commit di feat/kernel. Lapor: commit hash + test count + daftar bypass yang diuji.
