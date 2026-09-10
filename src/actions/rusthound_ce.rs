//! rusthound_ce action: run a full RustHound-CE (BloodHound-CE) collection over
//! the certificate-authenticated LDAP session, into the current directory, zipped.
//!
//! Since RustHound-CE 2.5.13 the collection pipeline is a library call:
//! `run_collection(ldap, options)` takes an already-authenticated `ldap3::Ldap`
//! session and does the whole workflow (collect -> parse -> modules -> JSON/zip).
//! PassTheCert-rs already holds a certificate-authenticated session, so it passes
//! it straight in — no re-authentication.

use anyhow::{anyhow, Result};
use log::info;

use crate::args::Options;

use rusthound_ce::args::{CollectionMethod, Options as RhOptions};
use rusthound_ce::api::run_collection;

/// Map PassTheCert-rs args to a RustHound-CE `Options`.
///
/// Output goes to the current directory and is always zipped. Authentication
/// fields are empty (the session is already certificate-authenticated), and
/// `LdapOnly` is used since there are no SMB credentials under certificate auth.
fn build_rh_options(opts: &Options) -> RhOptions {
    RhOptions {
        domain: opts.domain.clone(),
        username: None,
        password: None,
        ldapfqdn: opts.ldapfqdn.clone(),
        ip: opts.ip.clone(),
        port: opts.port,
        name_server: "not set".to_string(),
        path: "./".to_string(),
        collection_method: CollectionMethod::LdapOnly,
        ldaps: opts.ldaps,
        dns_tcp: false,
        fqdn_resolver: false,
        hashes: None,
        kerberos: false,
        pfx: None,
        pfx_pass: None,
        crt: None,
        key: None,
        zip: true,
        verbose: log::LevelFilter::Info,
        ldap_filter: "(objectClass=*)".to_string(),
        cache: false,
        cache_buffer_size: 1000,
        resume: false,
    }
}

/// Run the RustHound-CE collection using the current certificate session.
pub async fn run(ldap: &mut ldap3::Ldap, opts: &Options) -> Result<()> {
    let rh = build_rh_options(opts);
    info!("[rusthound_ce] collecting {} into the current directory (zipped)", rh.domain.to_uppercase());

    let out = run_collection(ldap, &rh)
        .await
        .map_err(|e| anyhow!("rusthound-ce collection failed: {e}"))?;

    info!("[rusthound_ce] done. Output written to {out}");
    Ok(())
}