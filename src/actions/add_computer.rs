//! add_computer / del_computer: create or remove a machine account.
//! Mirrors PassTheCert ManageComputer.add_computer / delete_computer.

use std::collections::HashSet;

use anyhow::{anyhow, Result};
use ldap3::{Ldap, Scope, SearchEntry};
use log::info;

use crate::args::Options;

fn base_dn(domain: &str) -> String {
    domain.split('.').map(|p| format!("dc={p}")).collect::<Vec<_>>().join(",")
}

fn random_name() -> String {
    use rand::Rng;
    let s: String = rand::thread_rng()
        .sample_iter(&rand::distributions::Alphanumeric)
        .take(8)
        .map(|c| c as char)
        .collect::<String>()
        .to_uppercase();
    format!("DESKTOP-{s}$")
}

fn pwd_utf16(p: &str) -> Vec<u8> {
    format!("\"{p}\"").encode_utf16().flat_map(|c| c.to_le_bytes()).collect()
}

async fn find_dn(ldap: &mut Ldap, base: &str, sam: &str) -> Result<Option<String>> {
    let filter = format!("(sAMAccountName={})", ldap3::ldap_escape(sam));
    let (rs, _) = ldap.search(base, Scope::Subtree, &filter, vec!["dn"])
        .await?.success()?;
    Ok(rs.into_iter().next().map(|e| SearchEntry::construct(e).dn))
}

pub async fn run(ldap: &mut Ldap, opts: &Options) -> Result<()> {
    let base = base_dn(&opts.domain);
    let group = opts.computer_group.as_deref()
        .map(str::to_string)
        .unwrap_or_else(|| format!("CN=Computers,{base}"));
    let name = opts.computer_name.clone()
        .map(|n| if n.ends_with('$') { n } else { format!("{n}$") })
        .unwrap_or_else(random_name);
    let pass = opts.computer_pass.clone()
        .unwrap_or_else(|| {
            use rand::Rng;
            rand::thread_rng()
                .sample_iter(&rand::distributions::Alphanumeric)
                .take(32).map(|c| c as char).collect()
        });

    if find_dn(ldap, &base, &name).await?.is_some() {
        return Err(anyhow!("computer account {name} already exists"));
    }

    let hostname = name.trim_end_matches('$');
    let dn = format!("CN={hostname},{group}");
    let dns = format!("{hostname}.{}", opts.domain);

    let spns: HashSet<Vec<u8>> = [
        format!("HOST/{hostname}"),
        format!("HOST/{dns}"),
        format!("RestrictedKrbHost/{hostname}"),
        format!("RestrictedKrbHost/{dns}"),
    ].iter().map(|s| s.as_bytes().to_vec()).collect();

    let object_class: HashSet<Vec<u8>> = ["top","person","organizationalPerson","user","computer"]
        .iter().map(|s| s.as_bytes().to_vec()).collect();

    let attrs: Vec<(Vec<u8>, HashSet<Vec<u8>>)> = vec![
        (b"objectClass".to_vec(),          object_class),
        (b"sAMAccountName".to_vec(),        HashSet::from([name.as_bytes().to_vec()])),
        (b"dnsHostName".to_vec(),           HashSet::from([dns.as_bytes().to_vec()])),
        (b"userAccountControl".to_vec(),    HashSet::from([b"4096".to_vec()])), // WORKSTATION_TRUST_ACCOUNT
        (b"unicodePwd".to_vec(),            HashSet::from([pwd_utf16(&pass)])),
        (b"servicePrincipalName".to_vec(),  spns),
    ];

    ldap.add(&dn, attrs).await?.success()
        .map_err(|e| anyhow!("add_computer failed: {e}"))?;
    info!("[+] computer account '{name}' created with password: {pass}");
    Ok(())
}

pub async fn del_computer(ldap: &mut Ldap, opts: &Options) -> Result<()> {
    let name = opts.computer_name.as_deref()
        .ok_or_else(|| anyhow!("--computer-name required"))?;
    let name = if name.ends_with('$') { name.to_string() } else { format!("{name}$") };
    let base = base_dn(&opts.domain);
    let dn = find_dn(ldap, &base, &name).await?
        .ok_or_else(|| anyhow!("computer {name} not found"))?;
    ldap.delete(&dn).await?.success()
        .map_err(|e| anyhow!("del_computer failed: {e}"))?;
    info!("[+] computer account '{name}' deleted");
    Ok(())
}