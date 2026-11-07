//! Regressions for local audit findings #2 and #5. Run only in Windows Sandbox.
use super::*;
use crate::clock::{TEST_EPOCH, TestClock};
use crate::journal::InMemoryJournal;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Condvar, OnceLock};
use std::time::Instant;

const PASSWORD: &str = "correta-cavalo-bateria";
const NEW_PASSWORD: &str = "nova-senha-mestra-1";
const SECRET: &[u8] = b"12345678901234567890";
const RECOVERY: [&str; 3] = ["ABCDE-FGHIJ", "KLMNO-PQRST", "UVWXY-Z2345"];

/// A read pauses after taking its snapshot. Without the transaction, a rival
/// takes the same stale snapshot. With it, the rival waits before store.load.
#[derive(Default)]
struct ControlledStore {
    value: Mutex<Option<Credentials>>,
    pause: AtomicBool,
    loads: AtomicUsize,
    released: Mutex<bool>,
    resume: Condvar,
    fail_save: AtomicBool,
}

impl ControlledStore {
    fn seed(&self) {
        static INITIAL: OnceLock<Credentials> = OnceLock::new();
        *self.value.lock().unwrap() = Some(
            INITIAL
                .get_or_init(|| Credentials {
                    password: hash_secret(PASSWORD),
                    totp_secret: SECRET.to_vec(),
                    last_step: TEST_EPOCH / 1000 / STEP_SECS - 1,
                    recovery: RECOVERY.iter().map(|code| hash_secret(&normalize_code(code))).collect(),
                    created_at: TEST_EPOCH,
                })
                .clone(),
        );
    }

    fn arm(&self) {
        self.loads.store(0, Ordering::SeqCst);
        *self.released.lock().unwrap() = false;
        self.pause.store(true, Ordering::SeqCst);
    }

    fn release(&self) {
        self.pause.store(false, Ordering::SeqCst);
        *self.released.lock().unwrap() = true;
        self.resume.notify_all();
    }
}

impl CredentialStore for ControlledStore {
    fn load(&self) -> anyhow::Result<Option<Credentials>> {
        let snapshot = self.value.lock().unwrap().clone();
        if self.pause.load(Ordering::SeqCst) {
            self.loads.fetch_add(1, Ordering::SeqCst);
            let mut released = self.released.lock().unwrap();
            while !*released {
                released = self.resume.wait(released).unwrap();
            }
        }
        Ok(snapshot)
    }

    fn save(&self, c: &Credentials) -> anyhow::Result<()> {
        anyhow::ensure!(!self.fail_save.swap(false, Ordering::SeqCst), "injected persistence failure");
        *self.value.lock().unwrap() = Some(c.clone());
        Ok(())
    }
}

fn fixture() -> (MasterAuth, Arc<TestClock>, Arc<ControlledStore>) {
    let clock = Arc::new(TestClock::new());
    let store = Arc::new(ControlledStore::default());
    store.seed();
    (MasterAuth::new(store.clone(), clock.clone(), Arc::new(InMemoryJournal::default())), clock, store)
}

fn wait_until(condition: impl Fn() -> bool) -> bool {
    let deadline = Instant::now() + Duration::from_secs(10);
    while !condition() {
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    true
}

fn race(
    auth: &MasterAuth,
    store: &ControlledStore,
    first: impl FnOnce(&MasterAuth) -> bool + Send,
    second: impl FnOnce(&MasterAuth) -> bool + Send,
) -> [bool; 2] {
    store.arm();
    let second_finished = AtomicBool::new(false);
    std::thread::scope(|scope| {
        let first_thread = scope.spawn(move || first(auth));
        if !wait_until(|| store.loads.load(Ordering::SeqCst) == 1) {
            store.release();
            let _ = first_thread.join();
            panic!("first operation did not reach its paused credential snapshot");
        }
        let second_thread = scope.spawn(|| {
            let result = second(auth);
            second_finished.store(true, Ordering::SeqCst);
            result
        });
        // This does not rely on a sleep to make a race likely. The corrected
        // contender reaches the held transaction; a mutant instead reaches a
        // second snapshot, or completes an unguarded session revocation.
        let contended = wait_until(|| {
            auth.transaction_waiters.load(Ordering::SeqCst) > 0 || store.loads.load(Ordering::SeqCst) > 1 || second_finished.load(Ordering::SeqCst)
        });
        store.release();
        let result = [first_thread.join().unwrap(), second_thread.join().unwrap()];
        assert!(contended, "rival did not contend with the paused operation");
        result
    })
}

#[test]
fn regeneration_cannot_bootstrap_totp_reset_from_password_alone() {
    let (auth, _, store) = fixture();
    let before = store.load().unwrap().unwrap();
    assert_eq!(auth.regenerate_recovery(PASSWORD, "").unwrap_err(), AuthError::BadCode);
    assert_eq!(auth.regenerate_recovery(PASSWORD, "not-a-code").unwrap_err(), AuthError::BadCode);
    let after = store.load().unwrap().unwrap();
    assert_eq!(after.recovery, before.recovery, "password-only attempt replaced the recovery codes");
    assert_eq!(after.last_step, before.last_step);
    // Positive control: possession of the current authenticator permits the
    // replacement, whose fresh recovery code can authorize a later reset.
    let proof = totp(SECRET, auth.step_now());
    let fresh = auth.regenerate_recovery(PASSWORD, &proof).unwrap();
    assert_eq!(fresh.len(), RECOVERY_CODES);
    assert_eq!(auth.regenerate_recovery(PASSWORD, &proof).unwrap_err(), AuthError::BadCode, "TOTP replay accepted");
    assert_eq!(auth.reset_password("owner", RECOVERY[0], NEW_PASSWORD).unwrap_err(), AuthError::BadCode);
    let enrollment = auth.begin_totp_reset("owner", PASSWORD, &fresh[0]).unwrap();
    let secret = data_encoding::BASE32_NOPAD.decode(enrollment.secret.as_bytes()).unwrap();
    auth.finish_totp_reset("owner", &totp(&secret, auth.step_now())).unwrap();
    assert_eq!(store.load().unwrap().unwrap().totp_secret, secret);
}

#[test]
fn regeneration_accepts_previous_recovery_but_not_password_or_proof_alone() {
    let (auth, _, store) = fixture();
    assert_eq!(auth.regenerate_recovery("senha-errada-longa", RECOVERY[0]).unwrap_err(), AuthError::BadPassword);
    assert_eq!(store.load().unwrap().unwrap().recovery.len(), RECOVERY.len());
    let fresh = auth.regenerate_recovery(PASSWORD, RECOVERY[0]).unwrap();
    assert_eq!(fresh.len(), RECOVERY_CODES);
    assert_eq!(auth.regenerate_recovery(PASSWORD, RECOVERY[0]).unwrap_err(), AuthError::BadCode);
    auth.reset_password("owner", &fresh[0], NEW_PASSWORD).unwrap();
    assert!(auth.authenticate("owner", NEW_PASSWORD).is_ok());
}

#[test]
fn correct_password_does_not_reset_failed_second_factor_budget() {
    let (auth, clock, _) = fixture();
    for _ in 0..FREE_FAILURES {
        assert_eq!(auth.regenerate_recovery(PASSWORD, "not-a-code").unwrap_err(), AuthError::BadCode);
    }
    assert!(matches!(auth.regenerate_recovery(PASSWORD, RECOVERY[0]), Err(AuthError::Throttled(_))));
    clock.advance(Duration::from_secs(31));
    assert!(auth.regenerate_recovery(PASSWORD, RECOVERY[0]).is_ok());
}

#[test]
fn competing_password_resets_cannot_consume_one_recovery_twice() {
    let (auth, _, store) = fixture();
    let results = race(
        &auth,
        &store,
        |a| a.reset_password("first", RECOVERY[0], NEW_PASSWORD).is_ok(),
        |a| a.reset_password("second", RECOVERY[0], "outra-senha-mestra-2").is_ok(),
    );
    assert_eq!(results, [true, false], "two competing requests consumed the same recovery code");
    let saved = store.load().unwrap().unwrap();
    assert_eq!(saved.recovery.len(), RECOVERY.len() - 1);
    assert!(verify_secret(NEW_PASSWORD, &saved.password));
    assert!(!auth.has_session("second"));
    assert!(auth.reset_password("second", RECOVERY[1], "outra-senha-mestra-2").is_ok(), "a distinct recovery code must work");
}

#[test]
fn competing_totp_checks_cannot_consume_one_step_twice() {
    let (auth, _, store) = fixture();
    let code = totp(SECRET, auth.step_now());
    let results = race(&auth, &store, |a| a.verify(&code), |a| a.verify(&code));
    assert_eq!(results, [true, false], "two competing requests accepted the same TOTP step");
    assert_eq!(store.load().unwrap().unwrap().last_step, auth.step_now());
}

#[test]
fn credential_mutations_preserve_a_concurrently_consumed_totp_step() {
    for operation in ["change-password", "reset-password", "regenerate-recovery"] {
        let (auth, _, store) = fixture();
        let code = totp(SECRET, auth.step_now());
        let results = race(
            &auth,
            &store,
            |a| a.verify(&code),
            |a| match operation {
                "change-password" => a.change_password("owner", PASSWORD, NEW_PASSWORD).is_ok(),
                "reset-password" => a.reset_password("owner", RECOVERY[0], NEW_PASSWORD).is_ok(),
                "regenerate-recovery" => a.regenerate_recovery(PASSWORD, RECOVERY[0]).is_ok(),
                _ => unreachable!(),
            },
        );
        assert_eq!(results, [true, true], "{operation}: independent valid operations must both succeed");
        let saved = store.load().unwrap().unwrap();
        assert_eq!(saved.last_step, auth.step_now(), "{operation} restored the already consumed TOTP step");
        if operation == "regenerate-recovery" {
            assert_eq!(saved.recovery.len(), RECOVERY_CODES, "TOTP verification restored old recovery codes");
        } else {
            assert!(verify_secret(NEW_PASSWORD, &saved.password), "TOTP verification restored the old password");
        }
        assert!(!auth.verify(&code));
    }
}

#[test]
fn totp_reset_proof_consumption_survives_a_competing_password_change() {
    let (auth, _, store) = fixture();
    let results =
        race(&auth, &store, |a| a.begin_totp_reset("owner", PASSWORD, RECOVERY[0]).is_ok(), |a| a.change_password("owner", PASSWORD, NEW_PASSWORD).is_ok());
    assert_eq!(results, [true, true]);
    let saved = store.load().unwrap().unwrap();
    assert_eq!(saved.recovery.len(), RECOVERY.len() - 1, "password change resurrected consumed reset proof");
    assert!(verify_secret(NEW_PASSWORD, &saved.password));
    assert_eq!(auth.finish_totp_reset("owner", "123456").unwrap_err(), AuthError::NoPending, "password change must invalidate old pending authority");
}

#[test]
fn finishing_totp_reset_and_changing_password_preserve_both_changes() {
    let (auth, _, store) = fixture();
    let enrollment = auth.begin_totp_reset("owner", PASSWORD, RECOVERY[0]).unwrap();
    let secret = data_encoding::BASE32_NOPAD.decode(enrollment.secret.as_bytes()).unwrap();
    let code = totp(&secret, auth.step_now());
    let results = race(&auth, &store, |a| a.finish_totp_reset("owner", &code).is_ok(), |a| a.change_password("owner", PASSWORD, NEW_PASSWORD).is_ok());
    assert_eq!(results, [true, true]);
    let saved = store.load().unwrap().unwrap();
    assert_eq!(saved.totp_secret, secret, "password change restored the old authenticator");
    assert!(verify_secret(NEW_PASSWORD, &saved.password), "TOTP reset restored the old password");
}

#[test]
fn authentication_cannot_open_a_session_from_a_stale_password_snapshot() {
    let (auth, _, store) = fixture();
    let results = race(&auth, &store, |a| a.reset_password("first", RECOVERY[0], NEW_PASSWORD).is_ok(), |a| a.authenticate("second", PASSWORD).is_ok());
    assert_eq!(results, [true, false], "old password opened a session after the competing reset");
    assert!(!auth.has_session("second"));
    assert!(auth.authenticate("second", NEW_PASSWORD).is_ok());
}

#[test]
fn session_revocation_waits_for_an_authentication_already_in_progress() {
    for all in [false, true] {
        let (auth, _, store) = fixture();
        let results = race(
            &auth,
            &store,
            |a| a.authenticate("owner", PASSWORD).is_ok(),
            |a| {
                if all {
                    a.end_all_sessions();
                } else {
                    a.end_session("owner");
                }
                true
            },
        );
        assert_eq!(results, [true, true]);
        assert!(!auth.has_session("owner"), "authentication reopened a session after revocation returned");
    }
}

#[test]
fn persistence_failure_does_not_return_recovery_or_consume_the_proof() {
    let (auth, _, store) = fixture();
    let before = store.load().unwrap().unwrap();
    store.fail_save.store(true, Ordering::SeqCst);
    assert!(matches!(auth.regenerate_recovery(PASSWORD, RECOVERY[0]), Err(AuthError::Storage(_))));
    assert_eq!(store.load().unwrap().unwrap().recovery, before.recovery);
    assert!(auth.regenerate_recovery(PASSWORD, RECOVERY[0]).is_ok(), "proof remains valid when no successful write occurred");
}

#[test]
fn failed_enrollment_writes_keep_pending_and_do_not_open_sessions() {
    let (auth, _, store) = fixture();
    let old = store.load().unwrap().unwrap();
    let enrollment = auth.begin_totp_reset("owner", PASSWORD, RECOVERY[0]).unwrap();
    let secret = data_encoding::BASE32_NOPAD.decode(enrollment.secret.as_bytes()).unwrap();
    let code = totp(&secret, auth.step_now());
    store.fail_save.store(true, Ordering::SeqCst);
    assert!(matches!(auth.finish_totp_reset("owner", &code), Err(AuthError::Storage(_))));
    assert_eq!(store.load().unwrap().unwrap().totp_secret, old.totp_secret);
    assert!(!auth.has_session("owner"));
    auth.finish_totp_reset("owner", &code).unwrap();
    assert_eq!(store.load().unwrap().unwrap().totp_secret, secret);

    let store = Arc::new(ControlledStore::default());
    let auth = MasterAuth::new(store.clone(), Arc::new(TestClock::new()), Arc::new(InMemoryJournal::default()));
    let enrollment = auth.begin_setup("owner", PASSWORD).unwrap();
    let secret = data_encoding::BASE32_NOPAD.decode(enrollment.secret.as_bytes()).unwrap();
    let code = totp(&secret, auth.step_now());
    store.fail_save.store(true, Ordering::SeqCst);
    assert!(matches!(auth.finish_setup("owner", &code), Err(AuthError::Storage(_))));
    assert!(!auth.configured() && !auth.has_session("owner"));
    assert_eq!(auth.finish_setup("owner", &code).unwrap().len(), RECOVERY_CODES);
    assert!(auth.has_session("owner"));
}

#[test]
fn completed_mutations_invalidate_other_pending_totp_resets() {
    for operation in ["change-password", "reset-password", "regenerate-recovery", "finish-totp-reset"] {
        let (auth, _, _) = fixture();
        let stale = auth.begin_totp_reset("first", PASSWORD, RECOVERY[0]).unwrap();
        let stale_secret = data_encoding::BASE32_NOPAD.decode(stale.secret.as_bytes()).unwrap();
        match operation {
            "change-password" => auth.change_password("second", PASSWORD, NEW_PASSWORD).unwrap(),
            "reset-password" => {
                auth.reset_password("second", RECOVERY[1], NEW_PASSWORD).unwrap();
            }
            "regenerate-recovery" => {
                auth.regenerate_recovery(PASSWORD, RECOVERY[1]).unwrap();
            }
            "finish-totp-reset" => {
                let current = auth.begin_totp_reset("second", PASSWORD, RECOVERY[1]).unwrap();
                let current_secret = data_encoding::BASE32_NOPAD.decode(current.secret.as_bytes()).unwrap();
                auth.finish_totp_reset("second", &totp(&current_secret, auth.step_now())).unwrap();
            }
            _ => unreachable!(),
        }
        assert_eq!(auth.finish_totp_reset("first", &totp(&stale_secret, auth.step_now())).unwrap_err(), AuthError::NoPending, "{operation}");
    }
}
