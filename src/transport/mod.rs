//! Network transports (mirrors the RustHound-CE transport/ layout).
//!
//! * `ldap`: LDAP/LDAPS + StartTLS connection and authentication, including
//!   Pass-the-Certificate (Schannel) via a client certificate.
//! * `cert`: builds the rustls ClientConfig that carries the client
//!   certificate (PFX or PEM) for certificate authentication.
pub mod cert;
pub mod ldap;