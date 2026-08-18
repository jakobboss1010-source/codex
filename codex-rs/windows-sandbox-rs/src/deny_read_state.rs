use crate::acl::revoke_ace;
use crate::deny_read_acl::apply_deny_read_acls;
use crate::deny_read_acl::lexical_path_key;
use crate::logging::log_note;
use crate::setup::sandbox_dir;
use crate::to_wide;
use anyhow::Context;
use anyhow::Result;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeMap;
use std::collections::HashSet;
use std::ffi::OsStr;
use std::ffi::c_void;
use std::fs::File;
use std::fs::OpenOptions;
use std::io::Read;
use std::io::Write;
use std::os::windows::fs::OpenOptionsExt;
use std::path::Path;
use std::path::PathBuf;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;
use windows_sys::Win32::Foundation::CloseHandle;
use windows_sys::Win32::Foundation::ERROR_FILE_NOT_FOUND;
use windows_sys::Win32::Foundation::GetLastError;
use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::Storage::FileSystem::FILE_SHARE_DELETE;
use windows_sys::Win32::Storage::FileSystem::FILE_SHARE_READ;
use windows_sys::Win32::Storage::FileSystem::FILE_SHARE_WRITE;
use windows_sys::Win32::Storage::FileSystem::MOVEFILE_REPLACE_EXISTING;
use windows_sys::Win32::Storage::FileSystem::MOVEFILE_WRITE_THROUGH;
use windows_sys::Win32::Storage::FileSystem::MoveFileExW;
use windows_sys::Win32::Storage::FileSystem::ReplaceFileW;
use windows_sys::Win32::System::Threading::CreateMutexW;
use windows_sys::Win32::System::Threading::INFINITE;
use windows_sys::Win32::System::Threading::ReleaseMutex;
use windows_sys::Win32::System::Threading::WaitForSingleObject;

const DENY_READ_ACL_STATE_FILE: &str = "deny_read_acl_state.json";
const DENY_READ_ACL_STATE_MUTEX_NAME: &str = "Local\\CodexSandboxDenyReadAclState";
const WAIT_OBJECT_0: u32 = 0;
const WAIT_ABANDONED: u32 = 0x0000_0080;
const WAIT_FAILED: u32 = u32::MAX;

#[derive(Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
struct PersistentDenyReadAclState {
    principals: BTreeMap<String, Vec<PathBuf>>,
}

/// Reconciles the persistent deny-read ACEs owned by one sandbox principal.
///
/// Workspace-write and elevated sandbox sessions intentionally leave ACLs in
/// place after a command exits, because descendants may outlive the launcher.
/// That makes the ACL set stateful across runs. Persist the paths applied for
/// each SID, apply the new desired set first, and only then revoke stale paths
/// from the same SID so profile changes do not leave old deny-read ACEs behind.
///
/// # Safety
/// Caller must pass a valid SID pointer matching `principal_sid`.
pub unsafe fn sync_persistent_deny_read_acls(
    codex_home: &Path,
    principal_sid: &str,
    desired_paths: &[PathBuf],
    psid: *mut c_void,
) -> Result<Vec<PathBuf>> {
    let state_path = sandbox_dir(codex_home).join(DENY_READ_ACL_STATE_FILE);
    update_state(&state_path, |state| {
        let previous_paths = state
            .principals
            .get(principal_sid)
            .cloned()
            .unwrap_or_default();

        let applied_paths = unsafe { apply_deny_read_acls(desired_paths, psid) }?;
        let desired_keys = applied_paths
            .iter()
            .map(|path| lexical_path_key(path))
            .collect::<HashSet<_>>();

        for path in previous_paths {
            if !desired_keys.contains(&lexical_path_key(&path)) {
                revoke_ace(&path, psid);
            }
        }

        if applied_paths.is_empty() {
            state.principals.remove(principal_sid);
        } else {
            state
                .principals
                .insert(principal_sid.to_string(), applied_paths.clone());
        }

        Ok(applied_paths)
    })
}

fn update_state<T>(
    path: &Path,
    update: impl FnOnce(&mut PersistentDenyReadAclState) -> Result<T>,
) -> Result<T> {
    update_state_with_mutex_name(path, DENY_READ_ACL_STATE_MUTEX_NAME, update)
}

fn update_state_with_mutex_name<T>(
    path: &Path,
    mutex_name: &str,
    update: impl FnOnce(&mut PersistentDenyReadAclState) -> Result<T>,
) -> Result<T> {
    // ACL reconciliation and persistence form one cross-process transaction.
    // Locking only the JSON write would still permit stale reads and lost updates.
    let _guard = DenyReadAclStateMutexGuard::acquire(mutex_name)
        .context("acquire deny-read ACL state mutex")?;
    let mut state = load_state(path)?;
    let output = update(&mut state)?;
    store_state(path, &state)?;
    Ok(output)
}

struct DenyReadAclStateMutexGuard {
    handle: HANDLE,
}

impl DenyReadAclStateMutexGuard {
    fn acquire(name: &str) -> Result<Self> {
        let name = to_wide(OsStr::new(name));
        let handle = unsafe { CreateMutexW(std::ptr::null_mut(), 0, name.as_ptr()) };
        if handle == 0 {
            return Err(anyhow::anyhow!("CreateMutexW failed: {}", unsafe {
                GetLastError()
            }));
        }

        let wait_result = unsafe { WaitForSingleObject(handle, INFINITE) };
        match wait_result {
            WAIT_OBJECT_0 | WAIT_ABANDONED => Ok(Self { handle }),
            WAIT_FAILED => {
                let error = unsafe { GetLastError() };
                unsafe {
                    CloseHandle(handle);
                }
                Err(anyhow::anyhow!("WaitForSingleObject failed: {error}"))
            }
            other => {
                unsafe {
                    CloseHandle(handle);
                }
                Err(anyhow::anyhow!(
                    "WaitForSingleObject returned unexpected status: {other}"
                ))
            }
        }
    }
}

impl Drop for DenyReadAclStateMutexGuard {
    fn drop(&mut self) {
        unsafe {
            let _ = ReleaseMutex(self.handle);
            CloseHandle(self.handle);
        }
    }
}

fn load_state(path: &Path) -> Result<PersistentDenyReadAclState> {
    match read_state_bytes(path) {
        Ok(bytes) => match serde_json::from_slice(&bytes) {
            Ok(state) => Ok(state),
            Err(err) => {
                quarantine_invalid_state(path, &bytes, &err.to_string());
                Ok(PersistentDenyReadAclState::default())
            }
        },
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            Ok(PersistentDenyReadAclState::default())
        }
        Err(err) => {
            Err(err).with_context(|| format!("read deny-read ACL state {}", path.display()))
        }
    }
}

fn read_state_bytes(path: &Path) -> std::io::Result<Vec<u8>> {
    let mut file = open_state_for_read(path)?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    Ok(bytes)
}

fn open_state_for_read(path: &Path) -> std::io::Result<File> {
    OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .open(path)
}

fn store_state(path: &Path, state: &PersistentDenyReadAclState) -> Result<()> {
    let bytes = serde_json::to_vec_pretty(state).context("serialize deny-read ACL state")?;
    let parent = path
        .parent()
        .with_context(|| format!("deny-read ACL state path has no parent: {}", path.display()))?;
    let mut temporary = tempfile::NamedTempFile::new_in(parent).with_context(|| {
        format!(
            "create temporary deny-read ACL state in {}",
            parent.display()
        )
    })?;
    temporary
        .write_all(&bytes)
        .with_context(|| format!("write temporary deny-read ACL state for {}", path.display()))?;
    temporary
        .flush()
        .with_context(|| format!("flush temporary deny-read ACL state for {}", path.display()))?;
    temporary
        .as_file()
        .sync_all()
        .with_context(|| format!("sync temporary deny-read ACL state for {}", path.display()))?;
    let temporary_path = temporary.into_temp_path();

    install_state_file(path, &temporary_path)?;
    // The Windows replacement primitive moves the temporary path into place.
    // Dropping TempPath then attempts to remove its now-missing old name, which
    // is intentionally ignored by tempfile's Drop implementation.
    Ok(())
}

fn install_state_file(destination: &Path, replacement: &Path) -> Result<()> {
    let destination_wide = to_wide(destination.as_os_str());
    let replacement_wide = to_wide(replacement.as_os_str());
    let replaced = unsafe {
        ReplaceFileW(
            destination_wide.as_ptr(),
            replacement_wide.as_ptr(),
            std::ptr::null(),
            0,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    if replaced != 0 {
        return Ok(());
    }

    let replace_error = unsafe { GetLastError() };
    if replace_error != ERROR_FILE_NOT_FOUND {
        return Err(anyhow::anyhow!(
            "ReplaceFileW failed for {}: {replace_error}",
            destination.display()
        ));
    }

    let moved = unsafe {
        MoveFileExW(
            replacement_wide.as_ptr(),
            destination_wide.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    };
    if moved == 0 {
        return Err(anyhow::anyhow!(
            "MoveFileExW failed for {}: {}",
            destination.display(),
            unsafe { GetLastError() }
        ));
    }
    Ok(())
}

fn quarantine_invalid_state(path: &Path, bytes: &[u8], parse_error: &str) {
    let Some(parent) = path.parent() else {
        return;
    };
    let backup_path = invalid_state_backup_path(path);
    let source_wide = to_wide(path.as_os_str());
    let backup_wide = to_wide(backup_path.as_os_str());
    let moved = unsafe {
        MoveFileExW(
            source_wide.as_ptr(),
            backup_wide.as_ptr(),
            MOVEFILE_WRITE_THROUGH,
        )
    };
    if moved != 0 {
        log_note(
            &format!(
                "quarantined invalid deny-read ACL state {} to {} after parse failure: {parse_error}",
                path.display(),
                backup_path.display()
            ),
            Some(parent),
        );
        return;
    }

    let move_error = unsafe { GetLastError() };
    let backup_result = std::fs::write(&backup_path, bytes);
    log_note(
        &format!(
            "failed to move invalid deny-read ACL state {} aside ({move_error}); backup {}: {}",
            path.display(),
            backup_path.display(),
            match backup_result {
                Ok(()) => "written".to_string(),
                Err(err) => format!("failed: {err}"),
            }
        ),
        Some(parent),
    );
}

fn invalid_state_backup_path(path: &Path) -> PathBuf {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or(DENY_READ_ACL_STATE_FILE);
    path.with_file_name(format!(
        "{file_name}.corrupt-{}-{timestamp}",
        std::process::id()
    ))
}

#[cfg(test)]
#[path = "deny_read_state_tests.rs"]
mod tests;
