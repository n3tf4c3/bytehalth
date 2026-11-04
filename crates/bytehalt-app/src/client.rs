//! Cliente do serviço. Produção: pipe do sistema com dono SYSTEM verificado antes de enviar dados.
//! Desenvolvimento (`--dev`): pipe por usuário com dono = usuário atual. Sem fallback automático.

use bytehalt_ipc::{Command, Reply, call};
use bytehalt_windows::pipe::{OwnerRejected, SYSTEM_SID, connect};
use std::time::Duration;

#[derive(Clone)]
pub struct Client {
    pipe: String,
    owners: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Failure {
    /// O pipe existe mas não pertence ao serviço esperado.
    Rejected,
    /// Serviço ausente ou conexão interrompida.
    Unavailable,
    /// O serviço respondeu com erro (validação, não encontrado, recusa).
    Service(String),
    /// Configuração protegida: falta abrir a sessão com a senha mestra.
    AuthRequired(String),
}

impl Client {
    pub fn new(development: bool) -> anyhow::Result<Self> {
        Ok(if development {
            let me = bytehalt_windows::user::current_user_sid()?;
            Self { pipe: bytehalt_ipc::development_pipe(&me), owners: vec![me] }
        } else {
            Self { pipe: bytehalt_ipc::PRODUCTION_PIPE.into(), owners: vec![SYSTEM_SID.into()] }
        })
    }

    pub fn call(&self, command: Command) -> Result<Reply, Failure> {
        let mut pipe = connect(&self.pipe, &self.owners, Duration::from_secs(2))
            .map_err(|e| if e.downcast_ref::<OwnerRejected>().is_some() { Failure::Rejected } else { Failure::Unavailable })?;
        call(&mut pipe, command).map_err(|e| match e.downcast_ref::<bytehalt_ipc::ServiceError>() {
            Some(s) if s.code == bytehalt_ipc::ErrorCode::AuthRequired => Failure::AuthRequired(s.message.clone()),
            Some(s) => Failure::Service(s.message.clone()),
            None => Failure::Unavailable,
        })
    }
}

impl Failure {
    pub fn text(&self) -> String {
        match self {
            Self::Rejected => "Conexão recusada: o pipe não pertence ao serviço do ByteHalt.".into(),
            Self::Unavailable => "Serviço do ByteHalt indisponível.".into(),
            Self::Service(m) | Self::AuthRequired(m) => m.clone(),
        }
    }
}
