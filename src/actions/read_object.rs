//! read_object action: dump every attribute of a single AD object.
//!
//! Resolves a target by sAMAccountName, CN, or full DN, then performs a
//! Scope::Base search asking for all attributes (user + operational) and
//! prints them. Values that AD stores as binary (objectSid, objectGUID,
//! nTSecurityDescriptor, ...) or as raw integers (userAccountControl,
//! FILETIME timestamps) are decoded to a human-readable form; everything
//! else is printed as-is.
//!
//! Example:
//!   passthecert-rs <conn> --action read_object --target khal.drogo
//!   passthecert-rs <conn> --action read_object --target "MEEREEN$"
//!   passthecert-rs <conn> --action read_object \
//!       --target "CN=Domain Admins,CN=Users,DC=essos,DC=local"

use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, Result};
use ldap3::{Ldap, Scope, SearchEntry};
use log::{debug, info};

use crate::args::Options;

fn base_dn(domain: &str) -> String {
    domain.split('.').map(|p| format!("dc={p}")).collect::<Vec<_>>().join(",")
}

// Heuristic: does the string look like a distinguished name?
fn looks_like_dn(s: &str) -> bool {
    let l = s.to_ascii_lowercase();
    l.starts_with("cn=") || l.starts_with("ou=") || l.starts_with("dc=") || l.contains(",dc=")
}

// Resolve the target to a DN. Accepts a full DN, a sAMAccountName (with or
// without a trailing '$' for machine accounts), or a CN.
async fn resolve_dn(ldap: &mut Ldap, base: &str, target: &str) -> Result<String> {
    if looks_like_dn(target) {
        debug!("[read_object] target treated as DN: {target}");
        return Ok(target.to_string());
    }

    let dollar = format!("{target}$");
    let filter = format!(
        "(|(sAMAccountName={})(sAMAccountName={})(cn={})(name={}))",
        ldap3::ldap_escape(target),
        ldap3::ldap_escape(&dollar),
        ldap3::ldap_escape(target),
        ldap3::ldap_escape(target),
    );
    debug!("[read_object] resolve filter: {filter}");

    let (rs, _) = ldap
        .search(base, Scope::Subtree, &filter, vec!["dn"])
        .await?
        .success()?;
    let entry = rs
        .into_iter()
        .next()
        .ok_or_else(|| anyhow!("object '{target}' not found"))?;
    let dn = SearchEntry::construct(entry).dn;
    debug!("[read_object] resolved DN: {dn}");
    Ok(dn)
}

// FILETIME (100-ns ticks since 1601) -> readable UTC. Handles the "never"
// sentinels (0 and 0x7FFFFFFFFFFFFFFF) used by AD.
fn filetime_to_utc(ft: u64) -> String {
    if ft == 0 {
        return "(never / not set)".to_string();
    }
    if ft == 0x7FFF_FFFF_FFFF_FFFF {
        return "(never)".to_string();
    }
    let unix = ft / 10_000_000;
    if unix < 11_644_473_600 {
        return format!("(raw {ft})");
    }
    let secs = unix - 11_644_473_600;
    let (y, mo, d) = days_to_ymd(secs / 86400);
    format!(
        "{y:04}-{mo:02}-{d:02} {:02}:{:02}:{:02} UTC",
        (secs / 3600) % 24,
        (secs / 60) % 60,
        secs % 60
    )
}

fn days_to_ymd(mut days: u64) -> (u64, u64, u64) {
    let (n400, r) = (days / 146097, days % 146097);
    days = r;
    let (n100, r) = (days / 36524, days % 36524);
    let (n100, r) = if n100 == 4 { (3, 36524) } else { (n100, r) };
    days = r;
    let (n4, r) = (days / 1461, days % 1461);
    let (n1, r) = (r / 365, r % 365);
    let (n1, r) = if n1 == 4 { (3, 365) } else { (n1, r) };
    let year = n400 * 400 + n100 * 100 + n4 * 4 + n1 + 1970;
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let mdays = [31u64, if leap { 29 } else { 28 }, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    let mut doy = r;
    let mut month = 1u64;
    for &md in &mdays {
        if doy < md { break; }
        doy -= md;
        month += 1;
    }
    (year, month, doy + 1)
}

// Format a binary objectSid as S-1-5-21-....
fn format_sid(bytes: &[u8]) -> Option<String> {
    if bytes.len() < 8 {
        return None;
    }
    let revision = bytes[0];
    let sub_count = bytes[1] as usize;
    if bytes.len() < 8 + sub_count * 4 {
        return None;
    }
    // Authority is a 48-bit big-endian value.
    let authority = bytes[2..8].iter().fold(0u64, |acc, &b| (acc << 8) | b as u64);
    let mut s = format!("S-{revision}-{authority}");
    for i in 0..sub_count {
        let off = 8 + i * 4;
        let sub = u32::from_le_bytes([bytes[off], bytes[off + 1], bytes[off + 2], bytes[off + 3]]);
        s.push_str(&format!("-{sub}"));
    }
    Some(s)
}

// Format a binary objectGUID as the canonical Windows GUID string
// (Data1/Data2/Data3 little-endian, Data4 as-is).
fn format_guid(b: &[u8]) -> Option<String> {
    if b.len() != 16 {
        return None;
    }
    Some(format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        b[3], b[2], b[1], b[0], b[5], b[4], b[7], b[6],
        b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15],
    ))
}

// Decode userAccountControl into its flag names.
fn format_uac(uac: u32) -> String {
    const FLAGS: &[(u32, &str)] = &[
        (0x0000_0001, "SCRIPT"),
        (0x0000_0002, "ACCOUNTDISABLE"),
        (0x0000_0008, "HOMEDIR_REQUIRED"),
        (0x0000_0010, "LOCKOUT"),
        (0x0000_0020, "PASSWD_NOTREQD"),
        (0x0000_0040, "PASSWD_CANT_CHANGE"),
        (0x0000_0080, "ENCRYPTED_TEXT_PWD_ALLOWED"),
        (0x0000_0100, "TEMP_DUPLICATE_ACCOUNT"),
        (0x0000_0200, "NORMAL_ACCOUNT"),
        (0x0000_0800, "INTERDOMAIN_TRUST_ACCOUNT"),
        (0x0000_1000, "WORKSTATION_TRUST_ACCOUNT"),
        (0x0000_2000, "SERVER_TRUST_ACCOUNT"),
        (0x0001_0000, "DONT_EXPIRE_PASSWORD"),
        (0x0002_0000, "MNS_LOGON_ACCOUNT"),
        (0x0004_0000, "SMARTCARD_REQUIRED"),
        (0x0008_0000, "TRUSTED_FOR_DELEGATION"),
        (0x0010_0000, "NOT_DELEGATED"),
        (0x0020_0000, "USE_DES_KEY_ONLY"),
        (0x0040_0000, "DONT_REQ_PREAUTH"),
        (0x0080_0000, "PASSWORD_EXPIRED"),
        (0x0100_0000, "TRUSTED_TO_AUTH_FOR_DELEGATION"),
        (0x0400_0000, "PARTIAL_SECRETS_ACCOUNT"),
    ];
    let names: Vec<&str> = FLAGS.iter().filter(|(f, _)| uac & f != 0).map(|(_, n)| *n).collect();
    if names.is_empty() {
        format!("{uac} (0x{uac:08x})")
    } else {
        format!("{uac} (0x{uac:08x}) [{}]", names.join(", "))
    }
}

// Attribute names whose STRING value is a FILETIME integer.
fn is_filetime_attr(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "pwdlastset"
            | "lastlogon"
            | "lastlogontimestamp"
            | "lastlogoff"
            | "accountexpires"
            | "badpasswordtime"
            | "lockouttime"
    )
}

// Attributes whose binary value is best shown as raw hex rather than decoded
// (large opaque blobs); we print length + a truncated hex preview.
fn is_opaque_blob(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "ntsecuritydescriptor"
            | "msds-allowedtoactonbehalfofotheridentity"
            | "msds-keycredentiallink"
            | "logonhours"
            | "usercertificate"
            | "cacertificate"
    )
}

/// Dump every attribute of the target object.
pub async fn run(ldap: &mut Ldap, opts: &Options) -> Result<()> {
    let target = opts
        .target
        .as_deref()
        .ok_or_else(|| anyhow!("--target required (sAMAccountName, CN, or DN)"))?;
    let base = base_dn(&opts.domain);
    let dn = resolve_dn(ldap, &base, target).await?;

    // "*" = all user attributes, "+" = all operational attributes.
    debug!("[read_object] base search on {dn}");
    let (rs, _) = ldap
        .search(&dn, Scope::Base, "(objectClass=*)", vec!["*", "+"])
        .await?
        .success()?;
    let entry = rs
        .into_iter()
        .next()
        .ok_or_else(|| anyhow!("object not found or not readable: {dn}"))?;
    let se = SearchEntry::construct(entry);

    info!("[*] {}", se.dn);

    // Merge and sort attribute names from both text and binary maps.
    let mut names: Vec<String> = se.attrs.keys().cloned().collect();
    for k in se.bin_attrs.keys() {
        if !se.attrs.contains_key(k) {
            names.push(k.clone());
        }
    }
    names.sort_by_key(|n| n.to_ascii_lowercase());

    for name in &names {
        // Text values
        if let Some(values) = se.attrs.get(name) {
            for v in values {
                info!("    {name}: {}", pretty_text(name, v));
            }
        }
        // Binary values
        if let Some(values) = se.bin_attrs.get(name) {
            for v in values {
                info!("    {name}: {}", pretty_binary(name, v));
            }
        }
    }

    debug!(
        "[read_object] dumped {} attribute name(s) at {}",
        names.len(),
        SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
    );
    Ok(())
}

// Render a text attribute value, decoding known integer-encoded attributes.
fn pretty_text(name: &str, value: &str) -> String {
    let lname = name.to_ascii_lowercase();
    if lname == "useraccountcontrol" {
        if let Ok(uac) = value.parse::<u32>() {
            return format_uac(uac);
        }
    }
    if is_filetime_attr(name) {
        if let Ok(ft) = value.parse::<u64>() {
            return format!("{value}  ({})", filetime_to_utc(ft));
        }
    }
    value.to_string()
}

// Render a binary attribute value, decoding SIDs, GUIDs, and opaque blobs.
fn pretty_binary(name: &str, value: &[u8]) -> String {
    let lname = name.to_ascii_lowercase();

    if lname == "objectsid" {
        if let Some(s) = format_sid(value) {
            return s;
        }
    }
    if lname == "objectguid" {
        if let Some(g) = format_guid(value) {
            return g;
        }
    }
    if is_opaque_blob(name) {
        let preview: String = value.iter().take(32).map(|b| format!("{b:02x}")).collect();
        let ellipsis = if value.len() > 32 { "..." } else { "" };
        return format!("<{} bytes> {preview}{ellipsis}", value.len());
    }

    // DNWithBinary and plain ASCII values (e.g. some come through bin_attrs):
    // show as text if printable, otherwise hex.
    if value.iter().all(|&b| b == 0x09 || b == 0x0a || b == 0x0d || (0x20..=0x7e).contains(&b)) {
        String::from_utf8_lossy(value).into_owned()
    } else {
        let hex: String = value.iter().take(48).map(|b| format!("{b:02x}")).collect();
        let ellipsis = if value.len() > 48 { "..." } else { "" };
        format!("<{} bytes> {hex}{ellipsis}", value.len())
    }
}