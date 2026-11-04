//! Integração do ByteHalt com o Windows. Tudo o que exige privilégio é usado pelo serviço; a
//! interface usa apenas o cliente do pipe, a ociosidade da sessão, a bandeja e a inicialização.
#![cfg(windows)]

pub mod acl;
pub mod bitlocker;
pub mod boot;
pub mod dpapi;
pub mod pipe;
mod restart;
pub mod secure_dir;
pub mod sim_vault;
pub mod sqlite;
pub mod user;
pub mod vhd;
mod wide;

pub use wide::{from_wide, wide};
