# Contributing

Thanks for taking the time to improve PassTheCert-rs. Small, focused pull requests are easier to review and make it safer for new contributors to learn the codebase.

## Before you start

PassTheCert-rs is a prototype for Pass-the-Certificate support in [RustHound-CE](https://github.com/g0h4n/RustHound-CE) ([issue #31](https://github.com/g0h4n/RustHound-CE/issues/31)). Check existing pull requests and recent commits before choosing a task. If the change is large, adds a new attack action, or changes how authentication works, open an issue or discussion first.

Please do not include credentials, domain data, private certificates, PFX/PEM files, or other sensitive information in commits, tests, screenshots, or pull requests. This is offensive tooling — use it only against systems you are authorized to test.

## Development setup

A current Rust toolchain is required (edition 2021; the current crate ecosystem needs Rust >= 1.85). Clone your fork and create a branch from the latest `main`:

```bash
git clone https://github.com/<your-user>/PassTheCert-rs.git
cd PassTheCert-rs
git remote add upstream https://github.com/<upstream-owner>/PassTheCert-rs.git
git fetch upstream
git switch -c feat/short-description upstream/main
```

Build and test the project with:

```bash
cargo build
cargo test --all-targets
cargo clippy --all-targets -- -A warnings
```

## Project layout

The code mirrors the RustHound-CE transport/ layout so actions can be ported upstream directly:

```
src/
├── main.rs               argument parsing, provider init, action dispatch
├── args.rs               CLI options (clap), same style as RustHound-CE
├── transport/
│   ├── cert.rs           rustls ClientConfig with the client certificate (PFX/PEM, TLS 1.2)
│   └── ldap.rs           connect + StartTLS/LDAPS + Schannel auth -> bound Ldap
└── actions/
    ├── whoami.rs         RFC 4532 Who am I?
    ├── ldapshell.rs      interactive LDAP shell
    ├── add_computer.rs   add / delete machine account
    ├── modify_user.rs    password reset / DCSync elevation
    ├── group.rs          add / remove group member
    ├── account.rs        enable / disable account (UAC ACCOUNTDISABLE)
    ├── rbcd.rs           RBCD read / write / remove / flush
    └── sd.rs             binary Security Descriptor / SID / ACE helpers
```

## Code changes

Keep one feature, bug fix, or documentation change per pull request. Each attack action lives in its own file under `actions/` and exposes a `run(&mut Ldap, &Options)` (or similar) entry point; add new actions the same way, then wire them into `args.rs` (the `--action` value_parser) and the `main.rs` dispatch.

Match the surrounding Rust style and avoid reformatting unrelated files. Keep the transport layer (`transport/`) independent from the actions, so both can be reused in RustHound-CE.

Add tests for non-trivial parsing logic (e.g. the SID/ACE/SD encoding in `sd.rs`). Keep unit tests inline at the bottom of the relevant module:

```rust
#[cfg(test)]
mod tests {
    // focused tests go here
}
```

Comments should explain intent or an unusual protocol constraint (Schannel behaviour, KB5014754 mapping, DC quirks), not restate the code.

## Pull requests

Before opening a pull request, update your branch, run the checks, and inspect the diff:

```bash
git fetch upstream
git rebase upstream/main
git diff upstream/main...HEAD --check
git status --short
```

The description should explain the problem, the approach, the scope, and how you validated it (which action, which transport, against what kind of DC — without leaking real environment details). Link the related issue when relevant.

## Commit messages

Use short English commit messages in imperative form. Conventional prefixes are preferred:

```text
feat: add group add_member/remove_member actions
fix: use ldap_escape for filter values
docs: document the StartTLS vs LDAPS transports
test: cover SID string encoding
```

## Credits and licensing

This project ports the technique and action set of [AlmondOffSec/PassTheCert](https://github.com/AlmondOffSec/PassTheCert). When contributing an action inspired by the original tool (or by Certipy), credit the source in the module header. Keep new dependencies pure-Rust and cross-platform where possible, consistent with the existing `ldap3` + `rustls` stack.

## Security reports

Do not disclose security-sensitive findings in a public issue. Contact the maintainer privately and include only the information needed to reproduce and fix the problem.