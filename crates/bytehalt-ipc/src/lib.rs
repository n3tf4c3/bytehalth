//! Protocolo entre interface e serviço (docs/ARCHITECTURE.md §6).
//!
//! - Enquadramento: 4 bytes little-endian com o tamanho + JSON UTF-8, máximo de 64 KiB.
//! - Envelope com versão e identificador; o comando é um `enum` fechado com payload tipado.
//!   Comando fora da lista ou payload malformado não desserializa e é recusado sem execução.

use bytehalt_core::auth::{Requirement, UnlockResult};
use bytehalt_core::engine::{OperationResult, Snapshot};
use bytehalt_core::journal::JournalEntry;
use bytehalt_core::locking::LockResult;
use bytehalt_core::model::{ProtectedResource, ProtectionGroup};
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};
use uuid::Uuid;

pub const VERSION: u32 = 1;
pub const MAX_MESSAGE: usize = 64 * 1024;
pub const PRODUCTION_PIPE: &str = "ByteHalt.Service.v1";

/// Pipe de desenvolvimento, por usuário, para o serviço em console sem privilégios.
pub fn development_pipe(user_sid: &str) -> String {
    format!("ByteHalt.Dev.v1.{user_sid}")
}

/// Lista fechada de comandos. Não existe comando genérico.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "command", content = "payload", deny_unknown_fields)]
pub enum Command {
    Ping,
    GetSnapshot,
    GetHistory {
        limit: u32,
    },
    SaveResource {
        resource: ProtectedResource,
    },
    DeleteResource {
        id: Uuid,
    },
    SaveGroup {
        group: ProtectionGroup,
    },
    DeleteGroup {
        id: Uuid,
    },
    LockResources {
        ids: Vec<Uuid>,
    },
    LockGroup {
        id: Uuid,
    },
    LockAll,
    GetUnlockRequirement {
        id: Uuid,
    },
    /// A senha é usada só para o desbloqueio e nunca registrada.
    Unlock {
        id: Uuid,
        passphrase: String,
        totp: Option<String>,
    },
    ReportSessionIdle {
        idle_secs: u64,
    },
    DiscoverVolumes,
    /// Somente no modo --simulate.
    SimulateActivity {
        id: Uuid,
    },
    /// Somente no modo --simulate.
    SimulateVolume {
        id: Uuid,
        present: Option<bool>,
        locked: Option<bool>,
        open_handles: Option<u32>,
        auto_unlock: Option<bool>,
    },
    /// Cofres (Fase 2). Analisar e preparar exigem que o chamador possa substituir a pasta.
    GetVaults,
    AnalyzeVault {
        path: String,
    },
    /// A senha só cria o protetor do BitLocker e nunca é registrada.
    PrepareVault {
        name: String,
        path: String,
        passphrase: String,
        max_bytes: u64,
    },
    /// Troca a pasta pelo cofre (confirmação explícita na interface).
    SwapVault {
        id: Uuid,
    },
    /// Descarta um cofre ainda não ativado; a pasta original não é tocada.
    DiscardVault {
        id: Uuid,
    },
    /// Apaga a pasta de reserva de um cofre ativo (confirmação explícita na interface).
    DeleteVaultReserve {
        id: Uuid,
    },
    /// Devolve a pasta ao normal (cópia de volta verificada) e apaga o disco do cofre.
    RemoveVault {
        id: Uuid,
    },
    /// Só no serviço em console (portátil): encerra o serviço. O pipe do console aceita apenas o próprio usuário.
    StopConsole,
    /// Fase 3: senha mestra, autenticador e códigos de recuperação. Senhas e códigos nunca são registrados.
    GetAuthStatus,
    BeginAuthSetup {
        password: String,
    },
    FinishAuthSetup {
        code: String,
    },
    /// Abre a sessão de configuração (15 min) para o usuário que chama.
    Authenticate {
        password: String,
    },
    EndAuthSession,
    ChangeMasterPassword {
        current: String,
        new: String,
    },
    RegenerateRecoveryCodes {
        password: String,
    },
    /// Esqueceu a senha mestra: um código de recuperação (uso único) permite criar outra.
    ResetMasterPassword {
        recovery_code: String,
        new: String,
    },
    /// Celular novo ou perdido: senha mestra + código atual do aplicativo OU código de recuperação.
    BeginTotpReset {
        password: String,
        proof: String,
    },
    FinishTotpReset {
        code: String,
    },
}

impl Command {
    pub fn name(&self) -> &'static str {
        match self {
            Self::Ping => "Ping",
            Self::GetSnapshot => "GetSnapshot",
            Self::GetHistory { .. } => "GetHistory",
            Self::SaveResource { .. } => "SaveResource",
            Self::DeleteResource { .. } => "DeleteResource",
            Self::SaveGroup { .. } => "SaveGroup",
            Self::DeleteGroup { .. } => "DeleteGroup",
            Self::LockResources { .. } => "LockResources",
            Self::LockGroup { .. } => "LockGroup",
            Self::LockAll => "LockAll",
            Self::GetUnlockRequirement { .. } => "GetUnlockRequirement",
            Self::Unlock { .. } => "Unlock",
            Self::ReportSessionIdle { .. } => "ReportSessionIdle",
            Self::DiscoverVolumes => "DiscoverVolumes",
            Self::SimulateActivity { .. } => "SimulateActivity",
            Self::SimulateVolume { .. } => "SimulateVolume",
            Self::GetVaults => "GetVaults",
            Self::AnalyzeVault { .. } => "AnalyzeVault",
            Self::PrepareVault { .. } => "PrepareVault",
            Self::SwapVault { .. } => "SwapVault",
            Self::DiscardVault { .. } => "DiscardVault",
            Self::DeleteVaultReserve { .. } => "DeleteVaultReserve",
            Self::RemoveVault { .. } => "RemoveVault",
            Self::StopConsole => "StopConsole",
            Self::GetAuthStatus => "GetAuthStatus",
            Self::BeginAuthSetup { .. } => "BeginAuthSetup",
            Self::FinishAuthSetup { .. } => "FinishAuthSetup",
            Self::Authenticate { .. } => "Authenticate",
            Self::EndAuthSession => "EndAuthSession",
            Self::ChangeMasterPassword { .. } => "ChangeMasterPassword",
            Self::RegenerateRecoveryCodes { .. } => "RegenerateRecoveryCodes",
            Self::ResetMasterPassword { .. } => "ResetMasterPassword",
            Self::BeginTotpReset { .. } => "BeginTotpReset",
            Self::FinishTotpReset { .. } => "FinishTotpReset",
        }
    }

    /// Validação de limites antes de chegar ao motor.
    pub fn validate(&self) -> Result<(), String> {
        match self {
            Self::GetHistory { limit } if *limit == 0 || *limit > 500 => Err("Limite do histórico deve ficar entre 1 e 500.".into()),
            Self::LockResources { ids } if ids.len() > 256 => Err("Recursos demais no pedido.".into()),
            Self::Unlock { passphrase, totp, .. } if passphrase.len() > 256 || totp.as_ref().is_some_and(|t| t.len() > 16) => {
                Err("Credencial fora do tamanho permitido.".into())
            }
            Self::ReportSessionIdle { idle_secs } if *idle_secs > 7 * 86_400 => Err("Ociosidade fora do intervalo.".into()),
            Self::SimulateVolume { open_handles: Some(h), .. } if *h > 1000 => Err("Quantidade de arquivos simulados fora do intervalo.".into()),
            Self::AnalyzeVault { path } | Self::PrepareVault { path, .. } if path.len() > 1024 => Err("Caminho longo demais.".into()),
            Self::PrepareVault { name, passphrase, .. } if name.len() > 512 || passphrase.len() > 1024 => {
                Err("Nome ou senha fora do tamanho permitido.".into())
            }
            Self::BeginAuthSetup { password } | Self::Authenticate { password } | Self::RegenerateRecoveryCodes { password } if password.len() > 1024 => {
                Err("Senha fora do tamanho permitido.".into())
            }
            Self::ChangeMasterPassword { current, new } if current.len() > 1024 || new.len() > 1024 => Err("Senha fora do tamanho permitido.".into()),
            Self::ResetMasterPassword { recovery_code, new } if recovery_code.len() > 64 || new.len() > 1024 => {
                Err("Credencial fora do tamanho permitido.".into())
            }
            Self::BeginTotpReset { password, proof } if password.len() > 1024 || proof.len() > 64 => Err("Credencial fora do tamanho permitido.".into()),
            Self::FinishAuthSetup { code } | Self::FinishTotpReset { code } if code.len() > 64 => Err("Código fora do tamanho permitido.".into()),
            _ => Ok(()),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Request {
    pub version: u32,
    pub id: Uuid,
    /// Envelope aninhado: `{"command": "...", "payload": {...}}`. Campos desconhecidos são recusados.
    pub request: Command,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VolumeInfo {
    pub drive_letter: String,
    pub state: bytehalt_core::locking::LockState,
    pub is_system_volume: bool,
    pub auto_unlock: bool,
    pub detail: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value")]
pub enum Reply {
    Pong {
        version: String,
        simulated: bool,
    },
    Snapshot(Snapshot),
    History(Vec<JournalEntry>),
    Operation(OperationResult),
    Locks(Vec<LockResult>),
    Requirement(Requirement),
    Unlock(UnlockResult),
    Volumes {
        volumes: Vec<VolumeInfo>,
        warning: Option<String>,
    },
    Vaults(Vec<bytehalt_core::vault_manager::VaultView>),
    VaultPlan(Box<bytehalt_core::vault_manager::VaultPlan>),
    Vault(Box<bytehalt_core::vault::VaultRecord>),
    AuthStatus(bytehalt_core::master::AuthStatus),
    Enrollment(bytehalt_core::master::Enrollment),
    /// Códigos de recuperação: exibidos uma vez.
    RecoveryCodes(Vec<String>),
    Ack,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ErrorCode {
    BadRequest,
    UnsupportedVersion,
    Forbidden,
    NotFound,
    Validation,
    Internal,
    /// Configuração protegida pela senha mestra: abra a sessão com `Authenticate`.
    AuthRequired,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Response {
    pub version: u32,
    /// Nulo quando o pedido nem pôde ser lido.
    pub id: Option<Uuid>,
    pub result: Result<Reply, (ErrorCode, String)>,
}

impl Response {
    pub fn error(id: Option<Uuid>, code: ErrorCode, message: impl Into<String>) -> Self {
        Self { version: VERSION, id, result: Err((code, message.into())) }
    }
}

#[derive(Debug)]
pub enum FrameError {
    Io(std::io::Error),
    TooLarge(usize),
    Truncated,
}

impl std::fmt::Display for FrameError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "E/S do pipe: {e}"),
            Self::TooLarge(n) => write!(f, "Mensagem com tamanho inválido ({n} bytes)."),
            Self::Truncated => write!(f, "Mensagem truncada."),
        }
    }
}

impl std::error::Error for FrameError {}

pub fn write_frame(w: &mut impl Write, payload: &[u8]) -> Result<(), FrameError> {
    if payload.is_empty() || payload.len() > MAX_MESSAGE {
        return Err(FrameError::TooLarge(payload.len()));
    }
    let mut buf = Vec::with_capacity(payload.len() + 4);
    buf.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    buf.extend_from_slice(payload);
    w.write_all(&buf).map_err(FrameError::Io)?;
    w.flush().map_err(FrameError::Io)
}

/// Lê uma mensagem. `Ok(None)` em fim de fluxo limpo (antes do cabeçalho).
pub fn read_frame(r: &mut impl Read) -> Result<Option<Vec<u8>>, FrameError> {
    let mut header = [0u8; 4];
    let n = read_full(r, &mut header)?;
    if n == 0 {
        return Ok(None);
    }
    if n < 4 {
        return Err(FrameError::Truncated);
    }
    let len = u32::from_le_bytes(header) as usize;
    if len == 0 || len > MAX_MESSAGE {
        return Err(FrameError::TooLarge(len));
    }
    let mut body = vec![0u8; len];
    if read_full(r, &mut body)? != len {
        return Err(FrameError::Truncated);
    }
    Ok(Some(body))
}

fn read_full(r: &mut impl Read, buf: &mut [u8]) -> Result<usize, FrameError> {
    let mut total = 0;
    while total < buf.len() {
        match r.read(&mut buf[total..]) {
            Ok(0) => break,
            Ok(n) => total += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            // Pipe fechado pelo outro lado equivale a fim de fluxo.
            Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => break,
            Err(e) => return Err(FrameError::Io(e)),
        }
    }
    Ok(total)
}

/// Desserializa um pedido e valida envelope e limites.
pub fn parse_request(bytes: &[u8]) -> Result<Request, Response> {
    let request: Request = serde_json::from_slice(bytes).map_err(|_| Response::error(None, ErrorCode::BadRequest, "Mensagem inválida."))?;
    if request.id.is_nil() {
        return Err(Response::error(None, ErrorCode::BadRequest, "Pedido sem identificador."));
    }
    if request.version != VERSION {
        return Err(Response::error(Some(request.id), ErrorCode::UnsupportedVersion, "Versão de protocolo não suportada."));
    }
    request.request.validate().map_err(|m| Response::error(Some(request.id), ErrorCode::Validation, m))?;
    Ok(request)
}

/// Cliente genérico sobre um fluxo já conectado e verificado.
pub fn call(stream: &mut (impl Read + Write), command: Command) -> anyhow::Result<Reply> {
    let request = Request { version: VERSION, id: Uuid::new_v4(), request: command };
    write_frame(stream, &serde_json::to_vec(&request)?)?;
    let bytes = read_frame(stream)?.ok_or_else(|| anyhow::anyhow!("O serviço encerrou a conexão."))?;
    let response: Response = serde_json::from_slice(&bytes)?;
    anyhow::ensure!(response.id == Some(request.id), "Resposta não corresponde ao pedido.");
    response.result.map_err(|(code, message)| anyhow::Error::new(ServiceError { code, message }))
}

/// Erro devolvido pelo serviço (recusa, validação, não encontrado…).
#[derive(Debug, Clone)]
pub struct ServiceError {
    pub code: ErrorCode,
    pub message: String,
}

impl std::fmt::Display for ServiceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for ServiceError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn json(s: &str) -> Vec<u8> {
        s.as_bytes().to_vec()
    }

    #[test]
    fn json_invalido_e_recusado() {
        assert_eq!(parse_request(&json("{nao é json")).unwrap_err().result.unwrap_err().0, ErrorCode::BadRequest);
    }

    #[test]
    fn comando_fora_da_lista_e_recusado() {
        let id = Uuid::new_v4();
        for body in [
            format!(r#"{{"version":1,"id":"{id}","request":{{"command":"RunShell","payload":{{"cmd":"whoami"}}}}}}"#),
            format!(r#"{{"version":1,"id":"{id}","request":{{"command":999}}}}"#),
            format!(r#"{{"version":1,"id":"{id}","request":{{"command":"LockAll"}},"extra":true}}"#),
            format!(r#"{{"version":1,"id":"{id}","request":{{"command":"DeleteGroup","payload":{{"id":"todos"}}}}}}"#),
        ] {
            assert_eq!(parse_request(body.as_bytes()).unwrap_err().result.unwrap_err().0, ErrorCode::BadRequest, "{body}");
        }
    }

    #[test]
    fn versao_identificador_e_limites_sao_validados() {
        let id = Uuid::new_v4();
        let v2 = format!(r#"{{"version":2,"id":"{id}","request":{{"command":"Ping"}}}}"#);
        assert_eq!(parse_request(v2.as_bytes()).unwrap_err().result.unwrap_err().0, ErrorCode::UnsupportedVersion);
        let nil = format!(r#"{{"version":1,"id":"{}","request":{{"command":"Ping"}}}}"#, Uuid::nil());
        assert_eq!(parse_request(nil.as_bytes()).unwrap_err().result.unwrap_err().0, ErrorCode::BadRequest);
        let big = format!(r#"{{"version":1,"id":"{id}","request":{{"command":"GetHistory","payload":{{"limit":100000}}}}}}"#);
        assert_eq!(parse_request(big.as_bytes()).unwrap_err().result.unwrap_err().0, ErrorCode::Validation);
        let ok = format!(r#"{{"version":1,"id":"{id}","request":{{"command":"GetHistory","payload":{{"limit":50}}}}}}"#);
        assert_eq!(parse_request(ok.as_bytes()).unwrap().request, Command::GetHistory { limit: 50 });
    }

    #[test]
    fn enquadramento_ida_e_volta_e_limites() {
        let mut buf = Vec::new();
        write_frame(&mut buf, b"{\"a\":1}").unwrap();
        let mut r = std::io::Cursor::new(buf);
        assert_eq!(read_frame(&mut r).unwrap().unwrap(), b"{\"a\":1}");
        assert!(read_frame(&mut r).unwrap().is_none());
        assert!(matches!(write_frame(&mut Vec::new(), &vec![0; MAX_MESSAGE + 1]), Err(FrameError::TooLarge(_))));
        assert!(matches!(write_frame(&mut Vec::new(), &[]), Err(FrameError::TooLarge(0))));
        assert!(matches!(read_frame(&mut std::io::Cursor::new(vec![10, 0, 0, 0, 1, 2])), Err(FrameError::Truncated)));
        assert!(matches!(read_frame(&mut std::io::Cursor::new(vec![0xff, 0xff, 0xff, 0xff])), Err(FrameError::TooLarge(_))));
    }

    #[test]
    fn pedido_serializado_tem_o_formato_documentado() {
        let r = Request { version: 1, id: Uuid::nil(), request: Command::LockGroup { id: Uuid::nil() } };
        let s = serde_json::to_string(&r).unwrap();
        assert!(s.contains(r#""command":"LockGroup""#) && s.contains(r#""payload":{"id":"#), "{s}");
        let back: Request = serde_json::from_str(&s).unwrap();
        assert_eq!(back, r);
    }
}
