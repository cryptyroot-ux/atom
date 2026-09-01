#![forbid(unsafe_code)]

//! ATOM Sovereign Agent Runtime HTTP API server.
//!
//! Implements the operation surface of `spec/openapi.yaml`: mission control,
//! effect dispatch (through the `atom-effect` reducer), capability management,
//! evidence retrieval, ledger events, and brokered secret handles.
//!
//! State is stored in a single SQLite file via `atom_ledger` (ADR-004/006):
//! the ledger is the authoritative append-only store; live projections serve
//! the HTTP read path.

pub mod app;
pub mod error;
pub mod routes;
pub mod store;
