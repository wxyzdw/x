// SPDX-License-Identifier: MPL-2.0
//! PAM service module shim.
//!
//! Compiled only with `--features pam-module` as a cdylib
//! (`pam_namikaze_sentinel.so`). The PAM service-module ABI is declared by
//! hand (Linux-PAM is a stable C ABI; the workspace carries no third-party
//! crates). The hook extends the audit chain and enforces the failure
//! policy; capture follows the consent marker rule.

#![allow(unsafe_code)] // required by the PAM service-module ABI
#![cfg(feature = "pam-module")]

/// Linux-PAM return codes (subset used here).
const PAM_AUTH_ERR: i32 = 7;

/// Opaque PAM handle; the module never dereferences it.
#[repr(C)]
struct PamHandle {
    _private: [u8; 0],
}

type PamFlags = i32;

/// The audit hook on the authenticate stack.
pub struct NamikazeSentinel;

impl NamikazeSentinel {
    fn authenticate(_flags: PamFlags, _args: Vec<String>) -> i32 {
        let mut state = crate::load_state();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let policy = crate::FailurePolicy::new(3, 300);
        match policy.decide(&state, now) {
            crate::Decision::Capture => {
                let _ = crate::capture_image();
                let _ = crate::audit_append(&mut state, "capture", "pam-auth-failure");
                PAM_AUTH_ERR
            }
            crate::Decision::Lockout => {
                let _ = crate::audit_append(&mut state, "lockout", "pam-auth-failure");
                PAM_AUTH_ERR
            }
            crate::Decision::Log => {
                let _ = crate::audit_append(&mut state, "log", "pam-auth-failure");
                PAM_AUTH_ERR
            }
        }
    }
}

/// PAM service module entry point (auth stack).
///
/// # SAFETY
/// PAM guarantees `argv`/`argc` describe a valid char* array for the
/// duration of the module call; we only read borrowed strings and convert
/// them to owned data before doing any real work.
#[no_mangle]
pub extern "C" fn pam_sm_authenticate(
    _pamh: *const PamHandle,
    flags: PamFlags,
    argc: i32,
    argv: *const *const std::os::raw::c_char,
) -> i32 {
    let args = unsafe {
        // SAFETY: see fn-level contract; slice bounds come from PAM's argc.
        let argc = argc.max(0) as usize;
        if argv.is_null() {
            Vec::new()
        } else {
            std::slice::from_raw_parts(argv, argc)
                .iter()
                .map(|p| {
                    if p.is_null() {
                        String::new()
                    } else {
                        std::ffi::CStr::from_ptr(*p).to_string_lossy().into_owned()
                    }
                })
                .collect::<Vec<String>>()
        }
    };
    NamikazeSentinel::authenticate(flags, args)
}
