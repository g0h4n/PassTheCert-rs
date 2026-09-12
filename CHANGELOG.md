# Changelog

## 1.0.4 - 2026-09-12

Upgrade the interactive `ldapshell` from a raw line reader to a proper shell using rustyline. Command names are Tab-completed, the up/down arrows browse the session history, and the usual line-editing shortcuts (left/right, Ctrl-A/E/W/U/K, Ctrl-R history search) all work; previously these keys left raw escape sequences on the line and every command had to be retyped in full.

rustyline is blocking while the REPL is async, so each read runs in a `tokio::task::spawn_blocking` with the editor moved in and back out, keeping the runtime and the LDAP actions fully async. History is kept in memory only and never written to disk. `Ctrl-C` cancels the current line and keeps the shell open; `Ctrl-D` quits. No command, argument or action behaviour changed — only the input layer. New dependency: `rustyline`.

## 1.0.3 - 2026-09-12

Add the `read_object` action, dumping every attribute of a single AD object (user, computer, group, OU, container, ...) over the certificate-authenticated session. The target is resolved by sAMAccountName (with or without a trailing `$`), CN, name, or full DN, and a `Scope::Base` search requests both all user attributes (`*`) and all operational attributes (`+`).

Values are decoded for readability rather than printed raw: `objectSid` as `S-1-5-21-...`, `objectGUID` as a canonical Windows GUID, `userAccountControl` as its named flags (`NORMAL_ACCOUNT`, `ACCOUNTDISABLE`, `TRUSTED_FOR_DELEGATION`, `DONT_REQ_PREAUTH`, ...), FILETIME attributes (`pwdLastSet`, `lastLogon`, `accountExpires`, ...) as UTC dates with the AD "never" sentinels handled, and opaque blobs (`nTSecurityDescriptor`, `msDS-KeyCredentialLink`, `userCertificate`, ...) as a size plus hex preview. The action reuses the existing `--target` option and is also available as the `read_object` / `dump` / `get_object` / `read` command in the ldap-shell. Read-only: no object is modified.

## 1.0.2 - 2026-09-11

Add Shadow Credentials (Key Trust) support through four new actions operating on the `msDS-KeyCredentialLink` attribute of a target account: `add_shadow_cred`, `list_shadow_cred`, `remove_shadow_cred` and `flush_shadow_cred`. All four are available both as `--action` flags (with the new `--shadow-target` and `--shadow-key-id` options) and as interactive `ldapshell` commands, with `-v`/`-vv` debug and trace logging.

`add_shadow_cred` generates an RSA 2048 key pair, builds a `KEYCREDENTIALLINK_BLOB` ([MS-ADTS] 2.2.20), adds it to the target, and saves `<target>.crt` + `<target>.key` (PEM) ready for PKINIT with Certipy. Three implementation details were required to make PKINIT succeed against a live DC:

1. The `KeyMaterial` entry is encoded as a `BCRYPT_RSAKEY_BLOB` (the Windows-native format DSInternals/pywhisker use), not SPKI DER, SPKI DER is rejected by the KDC with `KDC_ERROR_CLIENT_NOT_TRUSTED`.

2. The certificate carries the target's UPN in a SubjectAltName `OtherName` (OID `1.3.6.1.4.1.311.20.2.3`) via rcgen's native `SanType::OtherName`; without it the KDC cannot map the request to the account and returns `Name mismatch`. A hand-rolled `CustomExtension` on the SAN OID is silently deduplicated by rcgen and must not be used.

3. RSA is used rather than EC P-256, which Certipy v5+ refuses for PKINIT.

`list_shadow_cred` reads the attribute in both its text and `;binary` transfer forms so the values are found regardless of how the DC returns them, and displays each DeviceID in Windows GUID (mixed-endian) format alongside the creation time. On some DCs (observed on Windows Server 2016) the Key Credential is consumed after the first successful PKINIT and disappears from the attribute; the recovered NT hash stays valid. A commented `custom_key_info` line in `src/actions/shadow_cred.rs` is provided to experiment with persistence.

## 1.0.1 - 2026-09-10

Add the `rusthound_ce` action, running a full [RustHound-CE](https://github.com/g0h4n/RustHound-CE) (BloodHound-CE) collection over the certificate-authenticated session into the current directory as a zipped archive, so a Pass-the-Certificate foothold can be turned straight into a BloodHound dataset without a separate credential.

## 1.0.0 - 2026-09-09

First commit. Pass-the-Certificate over LDAPS/StartTLS using Schannel implicit certificate mapping (no bind), with the core action set: `whoami`, `ldapshell` (interactive shell exposing every action), `add_computer`/`del_computer`, `modify_user` (password reset and `--elevate` for DCSync rights), `add_member`/`remove_member`, `enable_account`/`disable_account`, and Resource-Based Constrained Delegation management (`read_rbcd`/`write_rbcd`/`remove_rbcd`/`flush_rbcd`).