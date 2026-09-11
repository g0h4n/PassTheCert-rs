//! Pass-the-Certificate test tool (PassTheCert parity, Rust + ldap3 + rustls).
//! Usage: ptc-test -d DOMAIN -f DC_FQDN --crt u.crt --key u.key --action <action> [options] --ldaps

use anyhow::{anyhow, Result};

mod actions;
mod args;
mod transport;

#[tokio::main]
async fn main() -> Result<()> {
    let opts = args::extract_args();
    env_logger::Builder::new()
        .filter_level(opts.verbose)
        .format_timestamp(None)
        .init();

    rustls::crypto::ring::default_provider()
        .install_default()
        .map_err(|_| anyhow!("failed to install rustls crypto provider"))?;

    let mut ldap = transport::ldap::ldap_search(&opts).await?;
    log::info!("[+] certificate authentication OK");

    match opts.action.as_str() {
        "whoami"            => { actions::whoami::run(&mut ldap).await?; }
        "ldapshell"         => actions::ldapshell::run(&mut ldap, &opts).await?,
        "add_computer"      => actions::add_computer::run(&mut ldap, &opts).await?,
        "del_computer"      => actions::add_computer::del_computer(&mut ldap, &opts).await?,
        "modify_user"       => {
            if opts.elevate {
                actions::modify_user::elevate(&mut ldap, &opts).await?;
            } else {
                actions::modify_user::change_password(&mut ldap, &opts).await?;
            }
        }
        "add_member"        => actions::group::add_member(&mut ldap, &opts).await?,
        "remove_member"     => actions::group::remove_member(&mut ldap, &opts).await?,
        "enable_account"    => actions::account::enable(&mut ldap, &opts).await?,
        "disable_account"   => actions::account::disable(&mut ldap, &opts).await?,
        "read_rbcd"         => actions::rbcd::read(&mut ldap, &opts).await?,
        "write_rbcd"        => actions::rbcd::write(&mut ldap, &opts).await?,
        "remove_rbcd"       => actions::rbcd::remove(&mut ldap, &opts).await?,
        "flush_rbcd"        => actions::rbcd::flush(&mut ldap, &opts).await?,
        "rusthound_ce"      => actions::rusthound_ce::run(&mut ldap, &opts).await?,
        "list_shadow_cred"   => actions::shadow_cred::list(&mut ldap, &opts).await?,
        "add_shadow_cred"    => actions::shadow_cred::add(&mut ldap, &opts).await?,
        "remove_shadow_cred" => actions::shadow_cred::remove(&mut ldap, &opts).await?,
        "flush_shadow_cred"  => actions::shadow_cred::flush(&mut ldap, &opts).await?,
        other         => return Err(anyhow!("unknown action: {other}")),
    }

    let _ = ldap.unbind().await;
    Ok(())
}