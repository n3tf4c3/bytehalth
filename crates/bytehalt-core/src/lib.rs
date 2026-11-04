//! Domínio do ByteHalt (docs/ARCHITECTURE.md). Tudo aqui é lógica pura e testável:
//! relógio, persistência, BitLocker e sessão entram por traits.

pub mod auth;
pub mod clock;
pub mod engine;
pub mod inactivity;
pub mod journal;
pub mod locking;
pub mod master;
pub mod migrate;
pub mod model;
pub mod policy;
pub mod simulated;
pub mod vault;
pub mod vault_manager;
