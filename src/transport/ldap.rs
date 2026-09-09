//! LDAP transport with Pass-the-Certificate (Schannel) authentication.
//!
//! Two transports, because AD accepts the certificate differently depending on
//! the channel and the DC configuration:
//!
//!   * StartTLS on 389  -> SASL EXTERNAL bind. This is the classic PassTheCert
//!     path and works on most DCs. Some DCs (e.g. certain Server 2016) refuse
//!     it (authMethodNotSupported) or reset the connection.
//!
//!   * LDAPS on 636     -> implicit Schannel mapping. The DC maps the client
//!     certificate to an account at the TLS layer, with no explicit bind; we
//!     just confirm the mapped identity with whoami. Works where StartTLS does
//!     not (and is what Certipy's schannel_connect does).
//!
//! `--ldaps` selects LDAPS/636; the default is StartTLS/389.
//! In both cases a whoami confirms the mapped identity (parsed defensively to
//! avoid ldap3's internal panic on an empty response).

use anyhow::{anyhow, Result};
use ldap3::exop::WhoAmI;
use ldap3::{Ldap, LdapConnAsync, LdapConnSettings};
use log::{info, warn};

use super::cert;
use crate::args::Options;

/// Connect with a client certificate and return the authenticated `Ldap` session.
pub async fn ldap_search(opts: &Options) -> Result<Ldap> {
    let use_cert = opts.pfx.is_some() || opts.crt.is_some();
    if !use_cert {
        return Err(anyhow!("certificate auth requires --pfx, or both --crt and --key"));
    }

    let config = cert::build_client_config(
        opts.pfx.as_deref(),
        opts.pfx_pass.as_deref(),
        opts.crt.as_deref(),
        opts.key.as_deref(),
    )?;

    let target = opts
        .ldapfqdn
        .clone()
        .or_else(|| opts.ip.clone())
        .unwrap_or_else(|| opts.domain.clone());

    let (url, starttls) = if opts.ldaps {
        (format!("ldaps://{target}:{}", opts.port.unwrap_or(636)), false)
    } else {
        (format!("ldap://{target}:{}", opts.port.unwrap_or(389)), true)
    };

    info!(
        "connecting to {url} (domain {}, transport: {})",
        opts.domain,
        if starttls { "StartTLS" } else { "LDAPS" }
    );

    let settings = LdapConnSettings::new()
        .set_conn_timeout(std::time::Duration::from_secs(10))
        .set_config(config)
        .set_starttls(starttls);

    let (conn, mut ldap) = LdapConnAsync::with_settings(settings, &url).await?;
    ldap3::drive!(conn);
    info!("TLS established (client certificate presented)");

    if starttls {
        // StartTLS: authenticate with SASL EXTERNAL (classic path).
        info!("binding with SASL EXTERNAL (Schannel over StartTLS)");
        ldap.sasl_external_bind()
            .await
            .and_then(|r| r.success())
            .map_err(|e| {
                warn!("SASL EXTERNAL failed: {e}");
                warn!("Some DCs refuse SASL EXTERNAL over StartTLS; retry with --ldaps (636).");
                anyhow!("SASL EXTERNAL bind: {e}")
            })?;
        info!("[+] SASL EXTERNAL bind OK");
    } else {
        // LDAPS: implicit Schannel mapping, no explicit bind.
        info!("LDAPS: relying on implicit Schannel certificate mapping (no bind)");
    }

    // Confirm the mapped identity via whoami, in both transports.
    let authzid = whoami_identity(&mut ldap).await?;
    info!("[+] Pass-the-Certificate OK - Schannel identity: {authzid}");
    Ok(ldap)
}

/// Run whoami and return the authzId, parsing the raw value defensively so an
/// empty response yields a clean error instead of ldap3's internal panic.
async fn whoami_identity(ldap: &mut Ldap) -> Result<String> {
    let res = ldap
        .extended(WhoAmI)
        .await
        .map_err(|e| anyhow!("whoami request failed: {e}"))?
        .success()
        .map_err(|e| anyhow!("whoami failed: {e}"))?;

    match &res.0.val {
        Some(v) if !v.is_empty() => Ok(String::from_utf8_lossy(v).to_string()),
        _ => Err(anyhow!(
            "certificate not mapped by the DC (empty whoami). Check the cert SID \
             matches the target account, and that this transport is accepted \
             (try --ldaps if StartTLS did not map the certificate)."
        )),
    }
}