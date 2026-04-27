// API surface used incrementally by features #46-#55. Items appear `dead`
// until later tasks wire them in; the allow keeps clippy clean without
// scattering attributes across every module.
#![allow(dead_code)]

pub mod crypto;
pub mod handlers;
pub mod oauth;
pub mod session;
pub mod store;
pub mod totp;
pub mod webauthn;

pub use session::{AuthState, SessionKey};
pub use store::AuthStore;
