//! account actions: enable_account / disable_account.
//!
//! Toggles the ACCOUNTDISABLE (0x2) bit of userAccountControl on the target
//! account. Requires the mapped identity to have write access to the target's
//! userAccountControl (e.g. GenericWrite, or Domain Admin).

use std::collections::HashSet;

use anyhow::{anyhow, Result};
use ldap3::{Ldap, Mod, Scope, SearchEntry};
use log::info;

use crate::args::Options;

const UAC_ACCOUNTDISABLE: u32 = 0x0002;

fn base_dn(domain: &str) -> String {
    domain.split('.').map(|p| format!("dc={p}")).collect::<Vec<_>>().join(",")
}

/// Fetch (dn, current userAccountControl) for a sAMAccountName.
async fn get_uac(ldap: &mut Ldap, base: &str, sam: &str) -> Result<(String, u32)> {
    let filter = format!("(sAMAccountName={})", ldap3::ldap_escape(sam));
    let (rs, _) = ldap
        .search(base, Scope::Subtree, &filter, vec!["userAccountControl"])
        .await?
        .success()?;
    let entry = rs
        .into_iter()
        .next()
        .ok_or_else(|| anyhow!("account '{sam}' not found in LDAP"))?;
    let se = SearchEntry::construct(entry);
    let dn = se.dn.clone();
    let uac = se
        .attrs
        .get("userAccountControl")
        .and_then(|v| v.first())
        .and_then(|s| s.parse::<u32>().ok())
        .ok_or_else(|| anyhow!("could not read userAccountControl for '{sam}'"))?;
    Ok((dn, uac))
}

async fn set_uac(ldap: &mut Ldap, dn: &str, uac: u32) -> Result<()> {
    ldap.modify(
        dn,
        vec![Mod::Replace(
            b"userAccountControl".to_vec(),
            HashSet::from([uac.to_string().into_bytes()]),
        )],
    )
    .await?
    .success()
    .map_err(|e| anyhow!("failed to write userAccountControl (need write access): {e}"))?;
    Ok(())
}

/// enable_account: clear the ACCOUNTDISABLE bit.
pub async fn enable(ldap: &mut Ldap, opts: &Options) -> Result<()> {
    let target = opts
        .target
        .as_deref()
        .ok_or_else(|| anyhow!("--target (sAMAccountName) required"))?;
    let base = base_dn(&opts.domain);
    let (dn, uac) = get_uac(ldap, &base, target).await?;

    if uac & UAC_ACCOUNTDISABLE == 0 {
        info!("[!] account '{target}' is already enabled (UAC={uac})");
        return Ok(());
    }
    let new_uac = uac & !UAC_ACCOUNTDISABLE;
    set_uac(ldap, &dn, new_uac).await?;
    info!("[+] account '{target}' enabled (UAC {uac} -> {new_uac})");
    Ok(())
}

/// disable_account: set the ACCOUNTDISABLE bit.
pub async fn disable(ldap: &mut Ldap, opts: &Options) -> Result<()> {
    let target = opts
        .target
        .as_deref()
        .ok_or_else(|| anyhow!("--target (sAMAccountName) required"))?;
    let base = base_dn(&opts.domain);
    let (dn, uac) = get_uac(ldap, &base, target).await?;

    if uac & UAC_ACCOUNTDISABLE != 0 {
        info!("[!] account '{target}' is already disabled (UAC={uac})");
        return Ok(());
    }
    let new_uac = uac | UAC_ACCOUNTDISABLE;
    set_uac(ldap, &dn, new_uac).await?;
    info!("[+] account '{target}' disabled (UAC {uac} -> {new_uac})");
    Ok(())
}