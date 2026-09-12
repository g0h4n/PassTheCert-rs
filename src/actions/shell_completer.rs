//! rustyline helper for the interactive ldap-shell: command-name Tab
//! completion, plus the standard line editing / arrow-key history that
//! rustyline provides out of the box.
//!
//! Completion is intentionally limited to the first word (the command name):
//! it is fully static, needs no LDAP round-trip, and never blocks the async
//! REPL. Arguments are not completed.

use rustyline::completion::{Completer, Pair};
use rustyline::highlight::Highlighter;
use rustyline::hint::Hinter;
use rustyline::validate::Validator;
use rustyline::{Context, Helper};

/// Every command name (and alias) the shell accepts, used for Tab completion
/// and by `help`. Keep this in sync with the match arms in `ldapshell.rs`.
pub const COMMANDS: &[&str] = &[
    "help",
    "exit",
    "quit",
    "whoami",
    "search",
    "dn",
    "add_member",
    "del_member",
    "remove_member",
    "enable",
    "enable_account",
    "disable",
    "disable_account",
    "passwd",
    "reset_password",
    "elevate",
    "dcsync",
    "add_computer",
    "del_computer",
    "read_rbcd",
    "write_rbcd",
    "remove_rbcd",
    "flush_rbcd",
    "rusthound",
    "rusthound_ce",
    "read_object",
    "read",
    "dump",
    "get_object",
    "add_shadow_cred",
    "shadow_add",
    "list_shadow_cred",
    "shadow_list",
    "remove_shadow_cred",
    "shadow_remove",
    "flush_shadow_cred",
    "shadow_flush",
];

/// rustyline helper providing command-name completion only.
pub struct ShellHelper;

impl Completer for ShellHelper {
    type Candidate = Pair;

    fn complete(
        &self,
        line: &str,
        pos: usize,
        _ctx: &Context<'_>,
    ) -> rustyline::Result<(usize, Vec<Pair>)> {
        // Only complete while typing the first word (the command). Once there
        // is whitespace before the cursor, we're on an argument: no completion.
        let head = &line[..pos];
        if head.trim_start().contains(char::is_whitespace) {
            return Ok((pos, Vec::new()));
        }

        let word_start = head.len() - head.trim_start().len();
        let prefix = head.trim_start();

        let matches: Vec<Pair> = COMMANDS
            .iter()
            .filter(|c| c.starts_with(prefix))
            .map(|c| Pair {
                display: c.to_string(),
                replacement: c.to_string(),
            })
            .collect();

        Ok((word_start, matches))
    }
}

// No hints, no syntax highlighting, no multi-line validation: use the defaults.
impl Hinter for ShellHelper {
    type Hint = String;
}
impl Highlighter for ShellHelper {}
impl Validator for ShellHelper {}
impl Helper for ShellHelper {}