use std::io::Write;
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use tracing::{error, info};
use webauthn_authenticator_rs::{
    types::{CableRequestType, CableState, EnrollSampleStatus},
    ui::UiCallback,
};

#[derive(Debug, Clone)]
pub struct BridgeUi {
    pub rp_id: String,
    child: Arc<Mutex<Option<Child>>>,
    stdin: Arc<Mutex<Option<ChildStdin>>>,
    cancelled: Arc<AtomicBool>,
}

impl BridgeUi {
    pub fn new(rp_id: String) -> Self {
        Self {
            rp_id,
            child: Arc::new(Mutex::new(None)),
            stdin: Arc::new(Mutex::new(None)),
            cancelled: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn is_cancelled(&self) -> bool {
        if self.cancelled.load(Ordering::SeqCst) {
            return true;
        }
        if let Ok(mut guard) = self.child.lock() {
            if let Some(child) = guard.as_mut() {
                if let Ok(Some(status)) = child.try_wait() {
                    // Check if process exited specifically via cancellation (code 2 / EXIT_CODE_CANCEL)
                    if status.code() == Some(crate::ui::EXIT_CODE_CANCEL) {
                        self.cancelled.store(true, Ordering::SeqCst);
                        return true;
                    } else if status.code() == Some(0) {
                        // Exited cleanly after success
                        return false;
                    } else {
                        // Exited with error (e.g. no display server / headless mode)
                        // Take the dead child so we don't keep polling it; fallback to terminal QR!
                        let _ = guard.take();
                        return false;
                    }
                }
            }
        }
        false
    }

    #[allow(dead_code)]
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::SeqCst);
        self.close();
    }

    pub fn close(&self) {
        self.cancelled.store(true, Ordering::SeqCst);
        if let Ok(mut guard) = self.child.lock() {
            if let Some(mut child) = guard.take() {
                let _ = child.kill();
                let _ = child.wait();
            }
        }
    }

    pub fn notify_done(&self) {
        if let Ok(mut guard) = self.stdin.lock() {
            if let Some(stdin) = guard.as_mut() {
                let _ = writeln!(stdin, "DONE");
                let _ = stdin.flush();
            }
        }
    }
}

/// Resolves the executable path, handling Linux's `/proc/self/exe -> path (deleted)`
/// symlink behavior when a binary has been updated or recompiled on disk.
pub fn resolve_executable_path(mut exe: std::path::PathBuf) -> std::path::PathBuf {
    if !exe.exists() {
        let s = exe.to_string_lossy();
        if s.ends_with(" (deleted)") {
            let clean = s.trim_end_matches(" (deleted)");
            let clean_path = std::path::PathBuf::from(clean);
            if clean_path.exists() {
                exe = clean_path;
            }
        }
    }
    exe
}

impl UiCallback for BridgeUi {
    fn request_pin(&self) -> Option<String> {
        None
    }

    fn request_touch(&self) {
        info!("caBLE touch requested");
    }

    fn processing(&self) {
        info!("caBLE processing...");
    }

    fn fingerprint_enrollment_feedback(
        &self,
        _remaining_samples: u32,
        _feedback: Option<EnrollSampleStatus>,
    ) {
    }

    fn cable_qr_code(&self, _request_type: CableRequestType, url: String) {
        info!("caBLE QR code received for {}", self.rp_id);

        // Also render text QR in terminal for logs/headless debugging
        if let Ok(qr) = qrcode::QrCode::new(&url) {
            let code = qr
                .render::<qrcode::render::unicode::Dense1x2>()
                .dark_color(qrcode::render::unicode::Dense1x2::Light)
                .light_color(qrcode::render::unicode::Dense1x2::Dark)
                .build();
            println!("\n{code}\n");
        }

        // Spawn GUI window
        if let Ok(exe_path) = std::env::current_exe() {
            let exe = resolve_executable_path(exe_path);
            let mut cmd = if unsafe { libc::getuid() } == 0 {
                if let Ok(sudo_user) = std::env::var("SUDO_USER") {
                    let mut c = Command::new("runuser");
                    c.arg("-u").arg(&sudo_user).arg("--").arg(&exe);
                    let sudo_uid = std::env::var("SUDO_UID").unwrap_or_else(|_| "1000".into());
                    let xdg = format!("/run/user/{}", sudo_uid);
                    c.env("XDG_RUNTIME_DIR", &xdg);
                    if let Ok(w) = std::env::var("WAYLAND_DISPLAY") {
                        c.env("WAYLAND_DISPLAY", w);
                    } else if std::path::Path::new(&format!("{}/wayland-1", xdg)).exists() {
                        c.env("WAYLAND_DISPLAY", "wayland-1");
                    } else if std::path::Path::new(&format!("{}/wayland-0", xdg)).exists() {
                        c.env("WAYLAND_DISPLAY", "wayland-0");
                    }
                    c
                } else {
                    Command::new(exe)
                }
            } else {
                Command::new(exe)
            };

            cmd.arg("--ui")
                .arg("--rp")
                .arg(&self.rp_id)
                .arg("--url")
                .arg(&url)
                .stdin(Stdio::piped())
                .stdout(Stdio::null());

            match cmd.spawn() {
                Ok(mut child) => {
                    if let Some(stdin) = child.stdin.take() {
                        if let Ok(mut s) = self.stdin.lock() {
                            *s = Some(stdin);
                        }
                    }
                    if let Ok(mut c) = self.child.lock() {
                        *c = Some(child);
                    }
                }
                Err(e) => {
                    error!("Failed to spawn caBLE GUI modal: {:?}", e);
                }
            }
        }
    }

    fn dismiss_qr_code(&self) {
        info!("caBLE QR code dismissed (phone connected via BLE)");
        if let Ok(mut guard) = self.stdin.lock() {
            if let Some(stdin) = guard.as_mut() {
                let _ = writeln!(stdin, "QR_SCANNED");
                let _ = stdin.flush();
            }
        }
    }

    fn cable_status_update(&self, state: CableState) {
        info!("caBLE status update: {:?}", state);
        let msg = match state {
            CableState::ConnectingToTunnelServer => "Connecting to secure relay...",
            CableState::Handshaking => "Establishing encrypted tunnel...",
            CableState::WaitingForAuthenticatorResponse => "Phone connected! Waiting for Face ID / Touch ID...",
            CableState::Processing => "Processing passkey on phone...",
            _ => "Scan QR code with phone camera",
        };

        if let Ok(mut guard) = self.stdin.lock() {
            if let Some(stdin) = guard.as_mut() {
                let _ = writeln!(stdin, "STATUS:{}", msg);
                let _ = stdin.flush();
            }
        }
    }
}

impl Drop for BridgeUi {
    fn drop(&mut self) {
        if let Ok(mut guard) = self.child.lock() {
            if let Some(mut child) = guard.take() {
                let _ = child.kill();
                let _ = child.wait();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bridge_ui_init_not_cancelled() {
        let ui = BridgeUi::new("webauthn.io".to_string());
        assert_eq!(ui.rp_id, "webauthn.io");
        assert!(!ui.is_cancelled());
    }

    #[test]
    fn test_bridge_ui_cancel() {
        let ui = BridgeUi::new("webauthn.io".to_string());
        ui.cancel();
        assert!(ui.is_cancelled());
    }

    #[test]
    fn test_bridge_ui_close_marks_cancelled() {
        let ui = BridgeUi::new("webauthn.io".to_string());
        ui.close();
        assert!(ui.is_cancelled());
    }

    #[test]
    fn test_resolve_executable_path_existing() {
        let path = std::path::PathBuf::from("/bin/sh");
        let resolved = resolve_executable_path(path.clone());
        assert_eq!(resolved, path);
    }

    #[test]
    fn test_resolve_executable_path_deleted_suffix() {
        // When a binary is updated while running, Linux appends ' (deleted)'
        let fake_deleted = std::path::PathBuf::from("/bin/sh (deleted)");
        let resolved = resolve_executable_path(fake_deleted);
        assert_eq!(resolved, std::path::PathBuf::from("/bin/sh"));
    }

    #[test]
    fn test_resolve_executable_path_nonexistent_without_suffix() {
        let fake = std::path::PathBuf::from("/nonexistent/binary/path");
        let resolved = resolve_executable_path(fake.clone());
        assert_eq!(resolved, fake);
    }
}

