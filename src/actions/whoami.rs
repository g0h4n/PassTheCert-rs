//! whoami action: RFC 4532 "Who am I?" extended operation.
//!
//! Confirms the identity AD mapped from the presented client certificate.

use anyhow::{anyhow, Result};
use ldap3::exop::{WhoAmI, WhoAmIResp};
use ldap3::Ldap;
use log::info;

/// Run the whoami extended op and return the authzId (e.g. "u:ESSOS\\daenerys").
pub async fn run(ldap: &mut Ldap) -> Result<String> {
    let res = ldap
        .extended(WhoAmI)
        .await
        .map_err(|e| anyhow!("whoami request: {e}"))?
        .success()
        .map_err(|e| anyhow!("whoami: {e}"))?;
    let who = res.0.parse::<WhoAmIResp>();
    if who.authzid.is_empty() {
        return Err(anyhow!("server returned an empty identity (cert not mapped)"));
    }
    info!("[whoami] {}", who.authzid);
    Ok(who.authzid)
}