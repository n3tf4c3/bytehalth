//! Relógio injetável. A parede (UTC) e o tempo monotônico são separados para que os testes
//! simulem passagem de tempo e alterações suspeitas de horário sem tocar no relógio do Windows.

use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Milissegundos desde 1970-01-01T00:00:00Z.
pub type UtcMillis = i64;

pub trait Clock: Send + Sync {
    /// Relógio de parede (pode ser alterado pelo usuário/administrador).
    fn now_utc(&self) -> UtcMillis;
    /// Tempo monotônico desde um ponto fixo do processo (não muda com o relógio).
    fn monotonic(&self) -> Duration;
}

/// Sessão de boot: identificador que muda a cada reinício do Windows e tempo desde o boot.
pub trait BootSession: Send + Sync {
    fn boot_id(&self) -> String;
    fn uptime(&self) -> Duration;
}

pub struct SystemClock {
    start: Instant,
}

impl SystemClock {
    pub fn new() -> Self {
        Self { start: Instant::now() }
    }
}

impl Default for SystemClock {
    fn default() -> Self {
        Self::new()
    }
}

impl Clock for SystemClock {
    fn now_utc(&self) -> UtcMillis {
        SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as i64).unwrap_or(0)
    }

    fn monotonic(&self) -> Duration {
        self.start.elapsed()
    }
}

/// Relógio de teste: `advance` simula tempo real (parede e monotônico juntos);
/// `set_wall` simula alguém mudando o relógio do Windows (só a parede).
pub struct TestClock {
    state: Mutex<(UtcMillis, Duration)>,
}

/// 2026-11-03T12:00:00Z.
pub const TEST_EPOCH: UtcMillis = 1_793_707_200_000;

impl TestClock {
    pub fn new() -> Self {
        Self::starting_at(TEST_EPOCH)
    }

    pub fn starting_at(wall: UtcMillis) -> Self {
        Self { state: Mutex::new((wall, Duration::from_secs(3600))) }
    }

    pub fn advance(&self, by: Duration) {
        let mut s = self.state.lock().unwrap_or_else(|e| e.into_inner());
        s.0 += by.as_millis() as i64;
        s.1 += by;
    }

    pub fn set_wall(&self, wall: UtcMillis) {
        self.state.lock().unwrap_or_else(|e| e.into_inner()).0 = wall;
    }
}

impl Default for TestClock {
    fn default() -> Self {
        Self::new()
    }
}

impl Clock for TestClock {
    fn now_utc(&self) -> UtcMillis {
        self.state.lock().unwrap_or_else(|e| e.into_inner()).0
    }

    fn monotonic(&self) -> Duration {
        self.state.lock().unwrap_or_else(|e| e.into_inner()).1
    }
}

/// Sessão de boot de teste ligada a um [`TestClock`].
pub struct TestBoot {
    clock: std::sync::Arc<TestClock>,
    state: Mutex<(String, Duration)>,
}

impl TestBoot {
    pub fn new(clock: std::sync::Arc<TestClock>) -> Self {
        Self { clock, state: Mutex::new(("boot-1".into(), Duration::ZERO)) }
    }

    /// Simula reinício do Windows: novo identificador e uptime recomeçando.
    pub fn reboot(&self, new_id: &str) {
        let mono = self.clock.monotonic();
        *self.state.lock().unwrap_or_else(|e| e.into_inner()) = (new_id.into(), mono);
    }
}

impl BootSession for TestBoot {
    fn boot_id(&self) -> String {
        self.state.lock().unwrap_or_else(|e| e.into_inner()).0.clone()
    }

    fn uptime(&self) -> Duration {
        let offset = self.state.lock().unwrap_or_else(|e| e.into_inner()).1;
        self.clock.monotonic().saturating_sub(offset)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relogio_de_teste_separa_parede_e_monotonico() {
        let c = TestClock::new();
        let m0 = c.monotonic();
        c.advance(Duration::from_secs(10));
        assert_eq!(c.now_utc(), TEST_EPOCH + 10_000);
        assert_eq!(c.monotonic(), m0 + Duration::from_secs(10));
        c.set_wall(TEST_EPOCH - 86_400_000);
        assert_eq!(c.monotonic(), m0 + Duration::from_secs(10));
    }
}
