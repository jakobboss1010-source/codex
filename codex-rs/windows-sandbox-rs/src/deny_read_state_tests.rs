use super::*;
use pretty_assertions::assert_eq;
use std::process::Command;
use std::process::Stdio;
use std::sync::Arc;
use std::sync::Barrier;
use std::thread;
use std::time::Duration;
use std::time::Instant;
use tempfile::TempDir;

const CHILD_STATE_PATH_ENV: &str = "CODEX_TEST_DENY_READ_STATE_PATH";
const CHILD_MUTEX_NAME_ENV: &str = "CODEX_TEST_DENY_READ_MUTEX_NAME";
const CHILD_PRINCIPAL_ENV: &str = "CODEX_TEST_DENY_READ_PRINCIPAL";
const CHILD_READY_PATH_ENV: &str = "CODEX_TEST_DENY_READ_READY_PATH";
const CHILD_START_PATH_ENV: &str = "CODEX_TEST_DENY_READ_START_PATH";

#[test]
fn nul_filled_state_is_quarantined_and_recreated() {
    let temp = TempDir::new().expect("create temp dir");
    let state_path = temp.path().join(DENY_READ_ACL_STATE_FILE);
    let corrupt_bytes = vec![0_u8; 22];
    std::fs::write(&state_path, &corrupt_bytes).expect("write corrupt state");

    update_state_with_mutex_name(&state_path, &unique_mutex_name("recovery"), |_| Ok(()))
        .expect("recover state");

    assert_eq!(
        load_state(&state_path).expect("load recovered state"),
        PersistentDenyReadAclState::default()
    );
    let backup = std::fs::read_dir(temp.path())
        .expect("read temp dir")
        .filter_map(Result::ok)
        .find(|entry| {
            entry
                .file_name()
                .to_string_lossy()
                .starts_with("deny_read_acl_state.json.corrupt-")
        })
        .expect("find corrupt state backup");
    assert_eq!(
        std::fs::read(backup.path()).expect("read backup"),
        corrupt_bytes
    );
}

#[test]
fn replacement_succeeds_while_reader_holds_delete_shared_handle() {
    let temp = TempDir::new().expect("create temp dir");
    let state_path = temp.path().join(DENY_READ_ACL_STATE_FILE);
    let mut initial = PersistentDenyReadAclState::default();
    initial
        .principals
        .insert("initial".to_string(), vec![PathBuf::from(r"C:\initial")]);
    store_state(&state_path, &initial).expect("store initial state");
    let reader = open_state_for_read(&state_path).expect("open shared reader");

    let mut replacement = PersistentDenyReadAclState::default();
    replacement.principals.insert(
        "replacement".to_string(),
        vec![PathBuf::from(r"C:\replacement")],
    );
    store_state(&state_path, &replacement).expect("replace state");

    assert_eq!(
        load_state(&state_path).expect("load replacement"),
        replacement
    );
    drop(reader);
}

#[test]
fn concurrent_thread_updates_preserve_every_principal() {
    const WRITER_COUNT: usize = 8;

    let temp = TempDir::new().expect("create temp dir");
    let state_path = temp.path().join(DENY_READ_ACL_STATE_FILE);
    let mutex_name = unique_mutex_name("threads");
    let start = Arc::new(Barrier::new(WRITER_COUNT));
    let mut writers = Vec::new();

    for index in 0..WRITER_COUNT {
        let state_path = state_path.clone();
        let mutex_name = mutex_name.clone();
        let start = Arc::clone(&start);
        writers.push(thread::spawn(move || {
            start.wait();
            update_state_with_mutex_name(&state_path, &mutex_name, |state| {
                thread::sleep(Duration::from_millis(25));
                state.principals.insert(
                    format!("S-1-5-21-thread-{index}"),
                    vec![PathBuf::from(format!(r"C:\thread-{index}"))],
                );
                Ok(())
            })
            .expect("update state");
        }));
    }

    for writer in writers {
        writer.join().expect("join writer");
    }

    let state = load_state(&state_path).expect("load final state");
    assert_eq!(state.principals.len(), WRITER_COUNT);
}

#[test]
fn concurrent_process_updates_preserve_every_principal() {
    if std::env::var_os(CHILD_STATE_PATH_ENV).is_some() {
        run_process_update_child();
        return;
    }

    const WRITER_COUNT: usize = 6;
    const CHILD_TEST_NAME: &str =
        "deny_read_state::tests::concurrent_process_updates_preserve_every_principal";

    let temp = TempDir::new().expect("create temp dir");
    let state_path = temp.path().join(DENY_READ_ACL_STATE_FILE);
    let start_path = temp.path().join("start");
    let mutex_name = unique_mutex_name("processes");
    let test_exe = std::env::current_exe().expect("resolve test executable");
    let mut children = Vec::new();
    let mut ready_paths = Vec::new();

    for index in 0..WRITER_COUNT {
        let ready_path = temp.path().join(format!("ready-{index}"));
        let child = Command::new(&test_exe)
            .args(["--exact", CHILD_TEST_NAME, "--nocapture"])
            .env(CHILD_STATE_PATH_ENV, &state_path)
            .env(CHILD_MUTEX_NAME_ENV, &mutex_name)
            .env(CHILD_PRINCIPAL_ENV, format!("S-1-5-21-process-{index}"))
            .env(CHILD_READY_PATH_ENV, &ready_path)
            .env(CHILD_START_PATH_ENV, &start_path)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn child writer");
        children.push(child);
        ready_paths.push(ready_path);
    }

    let ready_deadline = Instant::now() + Duration::from_secs(15);
    while !ready_paths.iter().all(|path| path.exists()) {
        assert!(
            Instant::now() < ready_deadline,
            "child writers did not become ready"
        );
        thread::sleep(Duration::from_millis(10));
    }
    std::fs::write(&start_path, b"start").expect("release child writers");

    for child in children {
        let output = child.wait_with_output().expect("wait for child writer");
        assert!(
            output.status.success(),
            "child writer failed: status={}, stdout={}, stderr={}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    let state = load_state(&state_path).expect("load final state");
    assert_eq!(state.principals.len(), WRITER_COUNT);
}

fn run_process_update_child() {
    let state_path = PathBuf::from(
        std::env::var_os(CHILD_STATE_PATH_ENV).expect("state path environment variable"),
    );
    let mutex_name = std::env::var(CHILD_MUTEX_NAME_ENV).expect("mutex name environment variable");
    let principal = std::env::var(CHILD_PRINCIPAL_ENV).expect("principal environment variable");
    let ready_path = PathBuf::from(
        std::env::var_os(CHILD_READY_PATH_ENV).expect("ready path environment variable"),
    );
    let start_path = PathBuf::from(
        std::env::var_os(CHILD_START_PATH_ENV).expect("start path environment variable"),
    );

    std::fs::write(&ready_path, b"ready").expect("mark child ready");
    let start_deadline = Instant::now() + Duration::from_secs(15);
    while !start_path.exists() {
        assert!(
            Instant::now() < start_deadline,
            "parent did not release child writer"
        );
        thread::sleep(Duration::from_millis(10));
    }

    update_state_with_mutex_name(&state_path, &mutex_name, |state| {
        thread::sleep(Duration::from_millis(25));
        state
            .principals
            .insert(principal, vec![PathBuf::from(r"C:\process-deny")]);
        Ok(())
    })
    .expect("update state from child process");
}

fn unique_mutex_name(label: &str) -> String {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time")
        .as_nanos();
    format!(
        "Local\\CodexSandboxDenyReadAclStateTest-{}-{label}-{timestamp}",
        std::process::id()
    )
}
