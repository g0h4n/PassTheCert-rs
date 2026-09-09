//! LDAP actions over a certificate-authenticated session.
//! Mirrors the PassTheCert action set, plus group and account management.

pub mod account;
pub mod add_computer;
pub mod group;
pub mod ldapshell;
pub mod modify_user;
pub mod rbcd;
pub mod sd;
pub mod whoami;