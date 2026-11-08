//! Fase 3: senha mestra do ByteHalt, autenticador TOTP (RFC 6238) e códigos de recuperação.
//!
//! - **Senha mestra** (Argon2id, parâmetros OWASP): libera as alterações de configuração por uma
//!   sessão curta do mesmo usuário do Windows; nunca é guardada nem registrada.
//! - **TOTP** (HMAC-SHA1, 6 dígitos, 30 s, ±1 passo): segundo fator do desbloqueio depois de 24 h
//!   bloqueado (ou sem registro). Um código não vale duas vezes (último passo persistido).
//! - **Códigos de recuperação** (10, uso único, guardados só como hash): redefinem a senha mestra ou
//!   recadastram o autenticador quando o celular se perde.
//!
//! Primitivas criptográficas vêm de crates auditadas (argon2, hmac, sha1, subtle); nada aqui é
//! criptografia própria. O armazenamento (DPAPI de máquina) entra pelo [`CredentialStore`].

use crate::auth::TotpVerifier;
use crate::clock::{Clock, UtcMillis};
use crate::journal::{EventType, Journal, JournalEntry, Severity, append_or_log};
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::{Algorithm, Argon2, Params, Version};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha1::Sha1;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

pub const MIN_MASTER: usize = 12;
pub const MAX_MASTER: usize = 256;
pub const SESSION: Duration = Duration::from_secs(15 * 60);
pub const PENDING: Duration = Duration::from_secs(10 * 60);
pub const RECOVERY_CODES: usize = 10;
pub const STEP_SECS: i64 = 30;
pub const DIGITS: u32 = 6;
/// Tentativas livres de senha/código de recuperação antes da espera progressiva.
pub const FREE_FAILURES: u32 = 5;
pub const MAX_WAIT: Duration = Duration::from_secs(15 * 60);
pub const ISSUER: &str = "ByteHalt";

/// O que fica protegido por DPAPI. O segredo TOTP é apagado da memória ao descartar.
#[derive(Clone, Serialize, Deserialize)]
pub struct Credentials {
    /// PHC do Argon2id.
    pub password: String,
    pub totp_secret: Vec<u8>,
    /// Último passo TOTP aceito (impede reutilizar um código).
    pub last_step: i64,
    /// PHC de cada código de recuperação ainda não usado.
    pub recovery: Vec<String>,
    pub created_at: UtcMillis,
}

impl Drop for Credentials {
    fn drop(&mut self) {
        self.totp_secret.zeroize();
    }
}

pub trait CredentialStore: Send + Sync {
    fn load(&self) -> anyhow::Result<Option<Credentials>>;
    fn save(&self, c: &Credentials) -> anyhow::Result<()>;
}

#[derive(Default)]
pub struct InMemoryCredentials(Mutex<Option<Credentials>>);

impl CredentialStore for InMemoryCredentials {
    fn load(&self) -> anyhow::Result<Option<Credentials>> {
        Ok(self.0.lock().unwrap_or_else(|e| e.into_inner()).clone())
    }
    fn save(&self, c: &Credentials) -> anyhow::Result<()> {
        *self.0.lock().unwrap_or_else(|e| e.into_inner()) = Some(c.clone());
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthStatus {
    pub configured: bool,
    pub session_active: bool,
    pub session_secs_left: Option<u64>,
    pub recovery_left: usize,
    pub wait_secs: Option<u64>,
}

/// Cadastro do autenticador: segredo em Base32 e URI `otpauth://` (para o QR code).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Enrollment {
    pub secret: String,
    pub uri: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AuthError {
    NotConfigured,
    AlreadyConfigured,
    Weak(String),
    BadPassword,
    BadCode,
    NoPending,
    Throttled(u64),
    Storage(String),
}

impl AuthError {
    pub fn message(&self) -> String {
        match self {
            Self::NotConfigured => "A senha mestra ainda não foi criada.".into(),
            Self::AlreadyConfigured => "A senha mestra já foi criada.".into(),
            Self::Weak(m) => m.clone(),
            Self::BadPassword => "Senha mestra incorreta.".into(),
            Self::BadCode => "Código inválido, expirado ou já utilizado.".into(),
            Self::NoPending => "Cadastro do autenticador expirou; comece de novo.".into(),
            Self::Throttled(s) => format!("Muitas tentativas. Aguarde {s} s."),
            Self::Storage(m) => format!("Não foi possível gravar as credenciais: {m}"),
        }
    }
}

enum PendingKind {
    Setup { password: String },
    TotpReset,
}

struct Pending {
    kind: PendingKind,
    secret: Zeroizing<Vec<u8>>,
    until: Duration,
}

#[derive(Default)]
struct Inner {
    pending: HashMap<String, Pending>,
    sessions: HashMap<String, Duration>,
    failures: u32,
    blocked_until: Option<Duration>,
}

pub struct MasterAuth {
    store: Arc<dyn CredentialStore>,
    clock: Arc<dyn Clock>,
    journal: Arc<dyn Journal>,
    inner: Mutex<Inner>,
    // Serialize the entire load/check/consume/save operation, not individual
    // store calls. Every handler and TOTP verifier shares this instance.
    credentials_transaction: Mutex<()>,
    #[cfg(test)]
    transaction_waiters: std::sync::atomic::AtomicUsize,
}

type R<T> = Result<T, AuthError>;

fn argon() -> Argon2<'static> {
    // OWASP: Argon2id, 19 MiB, 2 iterações, 1 via.
    Argon2::new(Algorithm::Argon2id, Version::V0x13, Params::new(19 * 1024, 2, 1, None).expect("parâmetros Argon2 válidos"))
}

fn random(n: usize) -> Vec<u8> {
    let mut b = vec![0u8; n];
    getrandom::getrandom(&mut b).expect("gerador aleatório do sistema");
    b
}

pub fn hash_secret(secret: &str) -> String {
    let salt = SaltString::encode_b64(&random(16)).expect("sal");
    argon().hash_password(secret.as_bytes(), &salt).expect("Argon2").to_string()
}

pub fn verify_secret(secret: &str, phc: &str) -> bool {
    PasswordHash::new(phc).is_ok_and(|h| argon().verify_password(secret.as_bytes(), &h).is_ok())
}

pub fn password_issues(p: &str) -> Option<String> {
    let n = p.chars().count();
    if n < MIN_MASTER {
        return Some(format!("A senha mestra precisa de pelo menos {MIN_MASTER} caracteres."));
    }
    if n > MAX_MASTER {
        return Some(format!("A senha mestra pode ter até {MAX_MASTER} caracteres."));
    }
    if p.chars().any(char::is_control) {
        return Some("A senha mestra contém caracteres de controle.".into());
    }
    let first = p.chars().next();
    if p.chars().all(|c| Some(c) == first) {
        return Some("A senha mestra não pode repetir um único caractere.".into());
    }
    None
}

/// Código TOTP (RFC 6238 / RFC 4226) do passo `step`.
pub fn totp(secret: &[u8], step: i64) -> String {
    let mut mac = Hmac::<Sha1>::new_from_slice(secret).expect("HMAC aceita qualquer chave");
    mac.update(&(step as u64).to_be_bytes());
    let h = mac.finalize().into_bytes();
    let off = (h[h.len() - 1] & 0x0f) as usize;
    let bin = (u32::from(h[off]) & 0x7f) << 24 | u32::from(h[off + 1]) << 16 | u32::from(h[off + 2]) << 8 | u32::from(h[off + 3]);
    format!("{:0width$}", bin % 10u32.pow(DIGITS), width = DIGITS as usize)
}

fn normalize_code(c: &str) -> String {
    c.chars().filter(|c| c.is_ascii_alphanumeric()).map(|c| c.to_ascii_uppercase()).collect()
}

/// `XXXXX-XXXXX` em Base32 (50 bits).
fn new_recovery_code() -> String {
    let s = data_encoding::BASE32_NOPAD.encode(&random(7));
    format!("{}-{}", &s[..5], &s[5..10])
}

impl MasterAuth {
    pub fn new(store: Arc<dyn CredentialStore>, clock: Arc<dyn Clock>, journal: Arc<dyn Journal>) -> Self {
        Self {
            store,
            clock,
            journal,
            inner: Mutex::new(Inner::default()),
            credentials_transaction: Mutex::new(()),
            #[cfg(test)]
            transaction_waiters: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    fn transaction(&self) -> std::sync::MutexGuard<'_, ()> {
        // Tests witness a contender before releasing a paused store read;
        // the production lock remains the only synchronization mechanism.
        #[cfg(test)]
        self.transaction_waiters.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let guard = self.credentials_transaction.lock().unwrap_or_else(|e| e.into_inner());
        #[cfg(test)]
        self.transaction_waiters.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
        guard
    }

    fn invalidate_pending(&self) {
        self.inner().pending.clear();
    }

    fn inner(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn log(&self, event: EventType, severity: Severity, message: &str) {
        append_or_log(
            self.journal.as_ref(),
            JournalEntry { at: self.clock.now_utc(), event, severity, resource_id: None, message: message.into(), detail: None },
        );
    }

    fn load(&self) -> R<Option<Credentials>> {
        self.store.load().map_err(|e| AuthError::Storage(format!("{e:#}")))
    }

    fn save(&self, c: &Credentials) -> R<()> {
        self.store.save(c).map_err(|e| AuthError::Storage(format!("{e:#}")))
    }

    fn creds(&self) -> R<Credentials> {
        self.load()?.ok_or(AuthError::NotConfigured)
    }

    /// Falha fechada: credenciais ilegíveis contam como configuradas (ninguém cria outra senha mestra
    /// por cima de um arquivo corrompido).
    pub fn configured(&self) -> bool {
        !matches!(self.load(), Ok(None))
    }

    fn wait(&self) -> Option<u64> {
        let now = self.clock.monotonic();
        self.inner().blocked_until.filter(|u| *u > now).map(|u| (u - now).as_secs().max(1))
    }

    fn throttle(&self) -> R<()> {
        self.wait().map_or(Ok(()), |s| Err(AuthError::Throttled(s)))
    }

    fn failed(&self) {
        let now = self.clock.monotonic();
        let mut i = self.inner();
        i.failures += 1;
        if i.failures >= FREE_FAILURES {
            let extra = i.failures - FREE_FAILURES;
            let wait = Duration::from_secs(30u64.saturating_mul(1 << extra.min(10))).min(MAX_WAIT);
            i.blocked_until = Some(now + wait);
        }
    }

    fn succeeded(&self) {
        let mut i = self.inner();
        i.failures = 0;
        i.blocked_until = None;
    }

    fn check_password(&self, c: &Credentials, password: &str) -> R<()> {
        self.throttle()?;
        if verify_secret(password, &c.password) {
            Ok(())
        } else {
            self.failed();
            self.log(EventType::Warning, Severity::Warning, "Senha mestra incorreta.");
            Err(AuthError::BadPassword)
        }
    }

    fn open_session(&self, sid: &str) -> u64 {
        let until = self.clock.monotonic() + SESSION;
        self.inner().sessions.insert(sid.to_owned(), until);
        SESSION.as_secs()
    }

    pub fn status(&self, sid: &str) -> AuthStatus {
        let loaded = self.load();
        let configured = !matches!(loaded, Ok(None));
        let creds = loaded.ok().flatten();
        let now = self.clock.monotonic();
        let left = self.inner().sessions.get(sid).filter(|u| **u > now).map(|u| (*u - now).as_secs());
        AuthStatus {
            configured,
            session_active: left.is_some(),
            session_secs_left: left,
            recovery_left: creds.as_ref().map_or(0, |c| c.recovery.len()),
            wait_secs: self.wait(),
        }
    }

    pub fn has_session(&self, sid: &str) -> bool {
        let now = self.clock.monotonic();
        self.inner().sessions.get(sid).is_some_and(|u| *u > now)
    }

    pub fn end_session(&self, sid: &str) {
        let _transaction = self.transaction();
        self.inner().sessions.remove(sid);
    }

    /// Bloquear o Windows encerra todas as sessões de configuração.
    pub fn end_all_sessions(&self) {
        let _transaction = self.transaction();
        self.inner().sessions.clear();
    }

    fn enrollment(&self, sid: &str, kind: PendingKind) -> Enrollment {
        let secret = Zeroizing::new(random(20));
        let b32 = data_encoding::BASE32_NOPAD.encode(&secret);
        let account = format!("{ISSUER}%20({})", std::env::var("COMPUTERNAME").unwrap_or_else(|_| "PC".into()));
        let uri = format!("otpauth://totp/{ISSUER}:{account}?secret={b32}&issuer={ISSUER}&algorithm=SHA1&digits={DIGITS}&period={STEP_SECS}");
        let until = self.clock.monotonic() + PENDING;
        self.inner().pending.insert(sid.to_owned(), Pending { kind, secret, until });
        Enrollment { secret: b32, uri }
    }

    fn step_now(&self) -> i64 {
        self.clock.now_utc().div_euclid(1000).div_euclid(STEP_SECS)
    }

    /// Passo aceito para `code` (±1 passo), ou `None`.
    fn matching_step(&self, secret: &[u8], code: &str) -> Option<i64> {
        let code = normalize_code(code);
        if code.len() != DIGITS as usize {
            return None;
        }
        let now = self.step_now();
        (now - 1..=now + 1).find(|s| bool::from(totp(secret, *s).as_bytes().ct_eq(code.as_bytes())))
    }

    /// 1º passo do cadastro: valida a senha nova e gera o segredo (ainda não gravado).
    pub fn begin_setup(&self, sid: &str, password: &str) -> R<Enrollment> {
        let _transaction = self.transaction();
        if self.load()?.is_some() {
            return Err(AuthError::AlreadyConfigured);
        }
        if let Some(m) = password_issues(password) {
            return Err(AuthError::Weak(m));
        }
        Ok(self.enrollment(sid, PendingKind::Setup { password: hash_secret(password) }))
    }

    /// 2º passo: o primeiro código do aplicativo confirma o cadastro. Devolve os códigos de
    /// recuperação (exibidos uma vez) e abre a sessão de configuração.
    pub fn finish_setup(&self, sid: &str, code: &str) -> R<Vec<String>> {
        let _transaction = self.transaction();
        if self.load()?.is_some() {
            return Err(AuthError::AlreadyConfigured);
        }
        let now = self.clock.monotonic();
        let pending = self.inner().pending.remove(sid).filter(|p| p.until > now).ok_or(AuthError::NoPending)?;
        let PendingKind::Setup { password } = &pending.kind else { return Err(AuthError::NoPending) };
        let Some(step) = self.matching_step(&pending.secret, code) else {
            // Devolve o cadastro pendente: o usuário pode tentar o próximo código.
            self.inner().pending.insert(sid.to_owned(), pending);
            return Err(AuthError::BadCode);
        };
        let codes: Vec<String> = (0..RECOVERY_CODES).map(|_| new_recovery_code()).collect();
        let creds = Credentials {
            password: password.clone(),
            totp_secret: pending.secret.to_vec(),
            last_step: step,
            recovery: codes.iter().map(|c| hash_secret(&normalize_code(c))).collect(),
            created_at: self.clock.now_utc(),
        };
        if let Err(error) = self.save(&creds) {
            self.inner().pending.insert(sid.to_owned(), pending);
            return Err(error);
        }
        self.invalidate_pending();
        self.succeeded();
        // Senha nova: sessões abertas com a anterior (de qualquer usuário) deixam de valer.
        self.inner().sessions.clear();
        self.open_session(sid);
        self.log(EventType::ConfigurationChanged, Severity::Info, "Senha mestra e autenticador cadastrados.");
        Ok(codes)
    }

    /// Abre a sessão de configuração (15 min) para este usuário do Windows.
    pub fn authenticate(&self, sid: &str, password: &str) -> R<u64> {
        let _transaction = self.transaction();
        let c = self.creds()?;
        self.check_password(&c, password)?;
        self.succeeded();
        Ok(self.open_session(sid))
    }

    pub fn change_password(&self, sid: &str, current: &str, new: &str) -> R<()> {
        let _transaction = self.transaction();
        let mut c = self.creds()?;
        self.check_password(&c, current)?;
        if let Some(m) = password_issues(new) {
            return Err(AuthError::Weak(m));
        }
        c.password = hash_secret(new);
        self.save(&c)?;
        self.invalidate_pending();
        self.succeeded();
        // Senha nova: sessões abertas com a anterior (de qualquer usuário) deixam de valer.
        self.inner().sessions.clear();
        self.open_session(sid);
        self.log(EventType::ConfigurationChanged, Severity::Info, "Senha mestra alterada.");
        Ok(())
    }

    /// Replacing recovery codes requires possession of the existing second
    /// factor; otherwise a password alone could bootstrap a TOTP reset.
    pub fn regenerate_recovery(&self, password: &str, proof: &str) -> R<Vec<String>> {
        let _transaction = self.transaction();
        let mut c = self.creds()?;
        self.check_password(&c, password)?;
        self.consume_second_factor(&mut c, proof)?;
        let codes: Vec<String> = (0..RECOVERY_CODES).map(|_| new_recovery_code()).collect();
        c.recovery = codes.iter().map(|x| hash_secret(&normalize_code(x))).collect();
        self.save(&c)?;
        self.invalidate_pending();
        self.succeeded();
        self.log(EventType::ConfigurationChanged, Severity::Info, "Novos códigos de recuperação gerados; os anteriores deixaram de valer.");
        Ok(codes)
    }

    /// Consome um código de recuperação (uso único).
    fn consume_recovery(&self, c: &mut Credentials, code: &str) -> R<()> {
        self.throttle()?;
        let n = normalize_code(code);
        match c.recovery.iter().position(|h| verify_secret(&n, h)) {
            Some(i) => {
                c.recovery.remove(i);
                Ok(())
            }
            None => {
                self.failed();
                self.log(EventType::Warning, Severity::Warning, "Código de recuperação inválido.");
                Err(AuthError::BadCode)
            }
        }
    }

    /// Esqueceu a senha mestra: um código de recuperação permite criar outra.
    pub fn reset_password(&self, sid: &str, recovery_code: &str, new: &str) -> R<usize> {
        let _transaction = self.transaction();
        let mut c = self.creds()?;
        if let Some(m) = password_issues(new) {
            return Err(AuthError::Weak(m));
        }
        self.consume_recovery(&mut c, recovery_code)?;
        c.password = hash_secret(new);
        self.save(&c)?;
        self.invalidate_pending();
        self.succeeded();
        // Senha nova: sessões abertas com a anterior (de qualquer usuário) deixam de valer.
        self.inner().sessions.clear();
        self.open_session(sid);
        self.log(EventType::ConfigurationChanged, Severity::Warning, "Senha mestra redefinida com código de recuperação.");
        Ok(c.recovery.len())
    }

    fn consume_second_factor(&self, c: &mut Credentials, proof: &str) -> R<()> {
        self.throttle()?;
        let p = normalize_code(proof);
        if p.len() == DIGITS as usize && p.chars().all(|x| x.is_ascii_digit()) {
            let Some(step) = self.matching_step(&c.totp_secret, &p).filter(|s| *s > c.last_step) else {
                self.failed();
                return Err(AuthError::BadCode);
            };
            c.last_step = step;
        } else {
            self.consume_recovery(c, proof)?;
        }
        Ok(())
    }

    /// Recadastrar o autenticador (celular novo ou perdido): senha mestra + código atual do
    /// aplicativo OU um código de recuperação. Só a senha não basta: senão ela anularia o TOTP.
    pub fn begin_totp_reset(&self, sid: &str, password: &str, proof: &str) -> R<Enrollment> {
        let _transaction = self.transaction();
        let mut c = self.creds()?;
        self.check_password(&c, password)?;
        self.consume_second_factor(&mut c, proof)?;
        self.save(&c)?;
        self.succeeded();
        Ok(self.enrollment(sid, PendingKind::TotpReset))
    }

    pub fn finish_totp_reset(&self, sid: &str, code: &str) -> R<()> {
        let _transaction = self.transaction();
        let mut c = self.creds()?;
        let now = self.clock.monotonic();
        let pending = self.inner().pending.remove(sid).filter(|p| p.until > now).ok_or(AuthError::NoPending)?;
        if !matches!(pending.kind, PendingKind::TotpReset) {
            return Err(AuthError::NoPending);
        }
        let Some(step) = self.matching_step(&pending.secret, code) else {
            self.inner().pending.insert(sid.to_owned(), pending);
            return Err(AuthError::BadCode);
        };
        c.totp_secret = pending.secret.to_vec();
        c.last_step = step;
        if let Err(error) = self.save(&c) {
            self.inner().pending.insert(sid.to_owned(), pending);
            return Err(error);
        }
        self.invalidate_pending();
        self.succeeded();
        self.log(EventType::ConfigurationChanged, Severity::Warning, "Autenticador recadastrado.");
        Ok(())
    }
}

impl TotpVerifier for MasterAuth {
    fn enrolled(&self) -> bool {
        self.configured()
    }

    /// Código do desbloqueio: aceito uma única vez (o passo precisa ser posterior ao último usado).
    fn verify(&self, code: &str) -> bool {
        let _transaction = self.transaction();
        let Ok(Some(mut c)) = self.load() else { return false };
        match self.matching_step(&c.totp_secret, code) {
            Some(step) if step > c.last_step => {
                c.last_step = step;
                self.save(&c).is_ok()
            }
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clock::TestClock;
    use crate::journal::InMemoryJournal;

    const RFC: &[u8] = b"12345678901234567890";

    #[test]
    fn vetores_da_rfc_6238_sha1() {
        // RFC 6238, apêndice B (8 dígitos): 94287082, 07081804, 14050471 → últimos 6.
        assert_eq!(totp(RFC, 59 / 30), "287082");
        assert_eq!(totp(RFC, 1_111_111_109 / 30), "081804");
        assert_eq!(totp(RFC, 1_111_111_111 / 30), "050471");
    }

    fn auth() -> (MasterAuth, Arc<TestClock>, Arc<InMemoryCredentials>) {
        let clock = Arc::new(TestClock::new());
        let store = Arc::new(InMemoryCredentials::default());
        (MasterAuth::new(store.clone(), clock.clone(), Arc::new(InMemoryJournal::default())), clock, store)
    }

    fn code_now(a: &MasterAuth, secret: &[u8]) -> String {
        totp(secret, a.step_now())
    }

    fn setup(a: &MasterAuth, clock: &TestClock) -> (Vec<u8>, Vec<String>) {
        let e = a.begin_setup("S-1", "correta-cavalo-bateria").unwrap();
        assert!(e.uri.starts_with("otpauth://totp/ByteHalt:") && e.uri.contains(&e.secret));
        let secret = data_encoding::BASE32_NOPAD.decode(e.secret.as_bytes()).unwrap();
        let codes = a.finish_setup("S-1", &code_now(a, &secret)).unwrap();
        clock.advance(Duration::from_secs(30));
        (secret, codes)
    }

    #[test]
    fn cadastro_exige_senha_forte_e_o_primeiro_codigo() {
        let (a, clock, store) = auth();
        assert!(matches!(a.begin_setup("S-1", "curta"), Err(AuthError::Weak(_))));
        assert!(matches!(a.begin_setup("S-1", "aaaaaaaaaaaaaaa"), Err(AuthError::Weak(_))));
        let e = a.begin_setup("S-1", "correta-cavalo-bateria").unwrap();
        assert_eq!(a.finish_setup("S-1", "000000").unwrap_err(), AuthError::BadCode);
        assert!(!a.configured(), "nada gravado antes de confirmar");
        let secret = data_encoding::BASE32_NOPAD.decode(e.secret.as_bytes()).unwrap();
        let codes = a.finish_setup("S-1", &code_now(&a, &secret)).unwrap();
        assert_eq!(codes.len(), RECOVERY_CODES);
        assert!(codes.iter().all(|c| c.len() == 11 && c.as_bytes()[5] == b'-'));
        let s = a.status("S-1");
        assert!(s.configured && s.session_active && s.recovery_left == 10);
        // Nada em texto puro no que vai para o disco.
        let c = store.load().unwrap().unwrap();
        assert!(c.password.starts_with("$argon2id$") && !c.password.contains("correta"));
        assert!(c.recovery.iter().all(|h| h.starts_with("$argon2id$")));
        assert_eq!(a.begin_setup("S-1", "outra-senha-longa-1").unwrap_err(), AuthError::AlreadyConfigured);
        let _ = clock;
    }

    #[test]
    fn sessao_expira_e_e_por_usuario() {
        let (a, clock, _) = auth();
        setup(&a, &clock);
        a.end_session("S-1");
        assert!(!a.has_session("S-1"));
        assert_eq!(a.authenticate("S-1", "errada-errada-errada").unwrap_err(), AuthError::BadPassword);
        assert_eq!(a.authenticate("S-1", "correta-cavalo-bateria").unwrap(), SESSION.as_secs());
        assert!(a.has_session("S-1") && !a.has_session("S-2"));
        clock.advance(SESSION);
        assert!(!a.has_session("S-1"));
        a.authenticate("S-1", "correta-cavalo-bateria").unwrap();
        a.end_all_sessions();
        assert!(!a.has_session("S-1"));
    }

    #[test]
    fn tentativas_erradas_ativam_espera_progressiva() {
        let (a, clock, _) = auth();
        setup(&a, &clock);
        for _ in 0..FREE_FAILURES {
            assert_eq!(a.authenticate("S-1", "errada-errada-errada").unwrap_err(), AuthError::BadPassword);
        }
        assert!(matches!(a.authenticate("S-1", "correta-cavalo-bateria"), Err(AuthError::Throttled(_))), "nem a senha certa durante a espera");
        clock.advance(Duration::from_secs(31));
        assert!(a.authenticate("S-1", "correta-cavalo-bateria").is_ok());
    }

    #[test]
    fn codigo_totp_nao_vale_duas_vezes_e_aceita_um_passo_de_folga() {
        let (a, clock, _) = auth();
        let (secret, _) = setup(&a, &clock);
        let c = code_now(&a, &secret);
        assert!(a.verify(&c));
        assert!(!a.verify(&c), "reutilização recusada");
        clock.advance(Duration::from_secs(30));
        let previous = totp(&secret, a.step_now() - 1);
        assert!(!a.verify(&previous), "passo anterior ao último aceito");
        assert!(a.verify(&code_now(&a, &secret)));
        clock.advance(Duration::from_secs(90));
        assert!(!a.verify(&totp(&secret, a.step_now() - 3)), "fora da janela");
        assert!(!a.verify("12345"));
    }

    #[test]
    fn recuperacao_redefine_a_senha_e_cada_codigo_vale_uma_vez() {
        let (a, clock, _) = auth();
        let (_, codes) = setup(&a, &clock);
        assert!(matches!(a.reset_password("S-1", &codes[0], "curta"), Err(AuthError::Weak(_))));
        assert_eq!(a.reset_password("S-1", &codes[0].to_lowercase().replace('-', " "), "nova-senha-mestra-1").unwrap(), 9);
        assert_eq!(a.reset_password("S-1", &codes[0], "outra-senha-mestra-2").unwrap_err(), AuthError::BadCode);
        assert!(a.authenticate("S-1", "nova-senha-mestra-1").is_ok());
        let fresh = a.regenerate_recovery("nova-senha-mestra-1", &codes[1]).unwrap();
        assert_eq!(a.reset_password("S-1", &codes[1], "outra-senha-mestra-2").unwrap_err(), AuthError::BadCode, "antigos invalidados");
        assert_eq!(a.status("S-1").recovery_left, 10);
        assert!(a.reset_password("S-1", &fresh[3], "outra-senha-mestra-2").is_ok());
    }

    #[test]
    fn recadastrar_autenticador_exige_senha_e_segunda_prova() {
        let (a, clock, _) = auth();
        let (old, codes) = setup(&a, &clock);
        assert_eq!(a.begin_totp_reset("S-1", "correta-cavalo-bateria", "ZZZZZ-ZZZZZ").unwrap_err(), AuthError::BadCode, "só a senha não basta");
        assert_eq!(a.begin_totp_reset("S-1", "errada-errada-errada", &codes[0]).unwrap_err(), AuthError::BadPassword);
        let e = a.begin_totp_reset("S-1", "correta-cavalo-bateria", &codes[0]).unwrap();
        let new = data_encoding::BASE32_NOPAD.decode(e.secret.as_bytes()).unwrap();
        assert_eq!(a.finish_totp_reset("S-1", &code_now(&a, &old)).unwrap_err(), AuthError::BadCode);
        a.finish_totp_reset("S-1", &code_now(&a, &new)).unwrap();
        clock.advance(Duration::from_secs(30));
        assert!(!a.verify(&code_now(&a, &old)), "o autenticador antigo deixou de valer");
        assert!(a.verify(&code_now(&a, &new)));
        assert_eq!(a.status("S-1").recovery_left, 9);
    }

    // Achado de auditoria #17: senha nova encerra as sessões abertas com a anterior.
    #[test]
    fn trocar_ou_redefinir_a_senha_encerra_as_sessoes_dos_outros() {
        let (a, clock, _) = auth();
        let (_, codes) = setup(&a, &clock);
        a.authenticate("S-2", "correta-cavalo-bateria").unwrap();
        assert!(a.has_session("S-2"));
        a.change_password("S-1", "correta-cavalo-bateria", "nova-senha-mestra-9").unwrap();
        assert!(!a.has_session("S-2"), "sessão aberta com a senha antiga continuou valendo");
        assert!(a.has_session("S-1"), "quem trocou continua com a sessão");
        a.authenticate("S-2", "nova-senha-mestra-9").unwrap();
        a.reset_password("S-1", &codes[0], "outra-senha-mestra-7").unwrap();
        assert!(!a.has_session("S-2"), "a redefinição não encerrou a sessão do outro usuário");
    }
}

#[cfg(test)]
#[path = "master/audit_tests.rs"]
mod audit_tests;
