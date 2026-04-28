//! OS-level network integration for the overlay TUN device:
//! interface filtering, change watcher, host routes, and DNS plumbing.

pub mod dns;
pub mod filter;
pub mod overlay_dns;
pub mod routes;
pub mod watcher;
