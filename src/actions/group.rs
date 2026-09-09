//! group actions: add_member / remove_member.
//!
//! Adds or removes a user/computer to/from a group by modifying the group's
//! `member` attribute (LDAP MODIFY add/delete of the member DN). Requires the
//! mapped identity to have write access to the group (e.g. GenericWrite /
//! WriteProperty on `member`, or Domain Admin).

use std::collections::HashSet;

use anyhow::{anyhow, Result};
use ldap3::{Ldap, Mod, Scope, SearchEntry};
use log::info;

use crate::args::Options;

fn base_dn(domain: &str) -> String {
    domain.split('.').map(|p| format!("dc={p}")).collect::<Vec<_>>().join(",")
}

/// Resolve a sAMAccountName to its distinguishedName. Accepts users and
/// computers (append `$` yourself for machine accounts, or pass the exact SAM).
async fn resolve_dn(ldap: &mut Ldap, base: &str, sam: &str) -> Result<String> {
    let filter = format!("(sAMAccountName={})", ldap3::ldap_escape(sam));
    let (rs, _) = ldap
        .search(base, Scope::Subtree, &filter, vec!["dn"])
        .await?
        .success()?;
    rs.into_iter()
        .next()
        .map(|e| SearchEntry::construct(e).dn)
        .ok_or_else(|| anyhow!("object '{sam}' not found in LDAP"))
}

/// Resolve the target group's DN. The value may be a sAMAccountName
/// ("Domain Admins") or already a full DN ("CN=Domain Admins,CN=Users,...").
async fn resolve_group_dn(ldap: &mut Ldap, base: &str, group: &str) -> Result<String> {
    if group.to_lowercase().contains("dc=") {
        // looks like a DN already
        return Ok(group.to_string());
    }
    let filter = format!(
        "(&(objectClass=group)(sAMAccountName={}))",
        ldap3::ldap_escape(group)
    );
    let (rs, _) = ldap
        .search(base, Scope::Subtree, &filter, vec!["dn"])
        .await?
        .success()?;
    rs.into_iter()
        .next()
        .map(|e| SearchEntry::construct(e).dn)
        .ok_or_else(|| anyhow!("group '{group}' not found in LDAP"))
}

/// add_member: add `--target` (member) to `--group`.
pub async fn add_member(ldap: &mut Ldap, opts: &Options) -> Result<()> {
    let member = opts
        .target
        .as_deref()
        .ok_or_else(|| anyhow!("--target (member sAMAccountName) required"))?;
    let group = opts
        .group
        .as_deref()
        .ok_or_else(|| anyhow!("--group (group name or DN) required"))?;
    let base = base_dn(&opts.domain);

    let member_dn = resolve_dn(ldap, &base, member).await?;
    let group_dn = resolve_group_dn(ldap, &base, group).await?;

    ldap.modify(
        &group_dn,
        vec![Mod::Add(b"member".to_vec(), HashSet::from([member_dn.as_bytes().to_vec()]))],
    )
    .await?
    .success()
    .map_err(|e| anyhow!("add_member failed (need write on the group): {e}"))?;

    info!("[+] added '{member}' to group '{group}'");
    Ok(())
}

/// remove_member: remove `--target` (member) from `--group`.
pub async fn remove_member(ldap: &mut Ldap, opts: &Options) -> Result<()> {
    let member = opts
        .target
        .as_deref()
        .ok_or_else(|| anyhow!("--target (member sAMAccountName) required"))?;
    let group = opts
        .group
        .as_deref()
        .ok_or_else(|| anyhow!("--group (group name or DN) required"))?;
    let base = base_dn(&opts.domain);

    let member_dn = resolve_dn(ldap, &base, member).await?;
    let group_dn = resolve_group_dn(ldap, &base, group).await?;

    ldap.modify(
        &group_dn,
        vec![Mod::Delete(b"member".to_vec(), HashSet::from([member_dn.as_bytes().to_vec()]))],
    )
    .await?
    .success()
    .map_err(|e| anyhow!("remove_member failed (need write on the group): {e}"))?;

    info!("[+] removed '{member}' from group '{group}'");
    Ok(())
}