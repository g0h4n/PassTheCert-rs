//! Argument parsing (same style as RustHound-CE args.rs).
//! Only the options actually used by this tool are declared.
use clap::{value_parser, Arg, ArgAction, Command};

#[derive(Clone, Debug)]
pub struct Options {
    // Connection
    pub domain: String,
    pub ldapfqdn: Option<String>,
    pub ip: Option<String>,
    pub port: Option<u16>,
    pub ldaps: bool,
    // Certificate auth (issue #31)
    pub pfx: Option<String>,
    pub pfx_pass: Option<String>,
    pub crt: Option<String>,
    pub key: Option<String>,
    // Action
    pub action: String,
    // Manage user (modify_user)
    pub target: Option<String>,
    pub new_pass: Option<String>,
    pub elevate: bool,
    // Manage computer (add_computer / del_computer)
    pub computer_name: Option<String>,
    pub computer_pass: Option<String>,
    pub computer_group: Option<String>,
    // Group membership (add_member / remove_member)
    pub group: Option<String>,
    // RBCD (read/write/remove/flush)
    pub delegate_to: Option<String>,
    pub delegate_from: Option<String>,
    // Verbosity
    pub verbose: log::LevelFilter,
}

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

fn cli() -> Command {
    Command::new("ptc-test")
        .version(VERSION)
        .about("Pass-the-Certificate (Schannel) tool - PassTheCert parity (RustHound-CE issue #31)")
        .arg(
            Arg::new("v")
                .short('v')
                .help("Verbosity (-v debug, -vv trace)")
                .action(ArgAction::Count),
        )
        .next_help_heading("REQUIRED VALUES")
        .arg(
            Arg::new("domain")
                .short('d')
                .long("domain")
                .help("Domain name like: DOMAIN.LOCAL")
                .required(true)
                .value_parser(value_parser!(String)),
        )
        .next_help_heading("CONNECTION")
        .arg(
            Arg::new("ldapfqdn")
                .short('f')
                .long("ldapfqdn")
                .help("Domain Controller FQDN like: DC01.DOMAIN.LOCAL (preferred for cert mapping)")
                .required(false)
                .value_parser(value_parser!(String)),
        )
        .arg(
            Arg::new("ldapip")
                .short('i')
                .long("ldapip")
                .help("Domain Controller IP address like: 192.168.1.10")
                .required(false)
                .value_parser(value_parser!(String)),
        )
        .arg(
            Arg::new("ldapport")
                .short('P')
                .long("ldapport")
                .help("LDAP port [default: 636 with --ldaps, 389 otherwise]")
                .required(false)
                .value_parser(value_parser!(String)),
        )
        .arg(
            Arg::new("ldaps")
                .long("ldaps")
                .help("Use LDAPS 636 (implicit Schannel mapping); default is StartTLS 389 + SASL EXTERNAL")
                .required(false)
                .action(ArgAction::SetTrue),
        )
        .next_help_heading("CERTIFICATE AUTH (Pass-the-Certificate / Schannel)")
        .arg(
            Arg::new("pfx")
                .long("pfx")
                .help("Path to a PFX/PKCS#12 client certificate")
                .required(false)
                .value_parser(value_parser!(String)),
        )
        .arg(
            Arg::new("pfx-pass")
                .long("pfx-pass")
                .help("Password protecting the PFX file (optional)")
                .required(false)
                .value_parser(value_parser!(String)),
        )
        .arg(
            Arg::new("crt")
                .long("crt")
                .help("Path to a PEM client certificate (use with --key)")
                .required(false)
                .value_parser(value_parser!(String)),
        )
        .arg(
            Arg::new("key")
                .long("key")
                .help("Path to the PEM private key (use with --crt)")
                .required(false)
                .value_parser(value_parser!(String)),
        )
        .next_help_heading("ACTION")
        .arg(
            Arg::new("action")
                .long("action")
                .help("whoami | ldapshell | add_computer | del_computer | modify_user | \
                       add_member | remove_member | enable_account | disable_account | \
                       read_rbcd | write_rbcd | remove_rbcd | flush_rbcd [default: whoami]")
                .required(false)
                .value_parser([
                    "whoami", "ldapshell",
                    "add_computer", "del_computer",
                    "modify_user",
                    "add_member", "remove_member",
                    "enable_account", "disable_account",
                    "read_rbcd", "write_rbcd", "remove_rbcd", "flush_rbcd",
                ]),
        )
        .next_help_heading("MANAGE USER (modify_user)")
        .arg(
            Arg::new("target")
                .long("target")
                .help("sAMAccountName of the target user")
                .required(false)
                .value_parser(value_parser!(String)),
        )
        .arg(
            Arg::new("new-pass")
                .long("new-pass")
                .help("New password for the target user")
                .required(false)
                .value_parser(value_parser!(String)),
        )
        .arg(
            Arg::new("elevate")
                .long("elevate")
                .help("Grant the target account DCSync rights")
                .required(false)
                .action(ArgAction::SetTrue),
        )
        .next_help_heading("MANAGE COMPUTER (add_computer / del_computer)")
        .arg(
            Arg::new("computer-name")
                .long("computer-name")
                .help("Machine account sAMAccountName (COMPUTERNAME$); random if omitted")
                .required(false)
                .value_parser(value_parser!(String)),
        )
        .arg(
            Arg::new("computer-pass")
                .long("computer-pass")
                .help("Password for the new machine account; random if omitted")
                .required(false)
                .value_parser(value_parser!(String)),
        )
        .arg(
            Arg::new("computer-group")
                .long("computer-group")
                .help("Container for the machine account [default: CN=Computers,<baseDN>]")
                .required(false)
                .value_parser(value_parser!(String)),
        )
        .next_help_heading("GROUP MEMBERSHIP (add_member / remove_member)")
        .arg(
            Arg::new("group")
                .long("group")
                .help("Target group: sAMAccountName (\"Domain Admins\") or full DN")
                .required(false)
                .value_parser(value_parser!(String)),
        )
        .next_help_heading("RBCD (read/write/remove/flush_rbcd)")
        .arg(
            Arg::new("delegate-to")
                .long("delegate-to")
                .help("Target computer sAMAccountName (victim machine, append $)")
                .required(false)
                .value_parser(value_parser!(String)),
        )
        .arg(
            Arg::new("delegate-from")
                .long("delegate-from")
                .help("Source computer sAMAccountName (attacker-controlled, append $)")
                .required(false)
                .value_parser(value_parser!(String)),
        )
}

/// Extract all arguments into the `Options` structure.
pub fn extract_args() -> Options {
    let m = cli().get_matches();

    let action = m
        .get_one::<String>("action")
        .cloned()
        .unwrap_or_else(|| "whoami".to_string());

    let verbose = match m.get_count("v") {
        0 => log::LevelFilter::Info,
        1 => log::LevelFilter::Debug,
        _ => log::LevelFilter::Trace,
    };

    Options {
        domain:         m.get_one::<String>("domain").cloned().unwrap_or_default(),
        ldapfqdn:       m.get_one::<String>("ldapfqdn").cloned(),
        ip:             m.get_one::<String>("ldapip").cloned(),
        port:           m.get_one::<String>("ldapport").and_then(|p| p.parse::<u16>().ok()),
        ldaps:          m.get_flag("ldaps"),
        pfx:            m.get_one::<String>("pfx").cloned(),
        pfx_pass:       m.get_one::<String>("pfx-pass").cloned(),
        crt:            m.get_one::<String>("crt").cloned(),
        key:            m.get_one::<String>("key").cloned(),
        action,
        target:         m.get_one::<String>("target").cloned(),
        new_pass:       m.get_one::<String>("new-pass").cloned(),
        elevate:        m.get_flag("elevate"),
        computer_name:  m.get_one::<String>("computer-name").cloned(),
        computer_pass:  m.get_one::<String>("computer-pass").cloned(),
        computer_group: m.get_one::<String>("computer-group").cloned(),
        group:          m.get_one::<String>("group").cloned(),
        delegate_to:    m.get_one::<String>("delegate-to").cloned(),
        delegate_from:  m.get_one::<String>("delegate-from").cloned(),
        verbose,
    }
}