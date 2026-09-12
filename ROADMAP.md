# Roadmap

This roadmap tracks what PassTheCert-rs already does and what could be added.
The goal is parity with (and eventually more than) [AlmondOffSec/PassTheCert](https://github.com/AlmondOffSec/PassTheCert) and [Invoke-PassTheCert](https://github.com/The-Viper-One/Invoke-PassTheCert), while staying pure-Rust so the code can be ported into [RustHound-CE](https://github.com/g0h4n/RustHound-CE) ([issue #31](https://github.com/g0h4n/RustHound-CE/issues/31)).

## Authentication

- [x] Client certificate via PEM (`--crt` / `--key`) :white_check_mark:
- [x] Client certificate via PFX (`--pfx` / `--pfx-pass`) :white_check_mark:
- [x] LDAPS (636) — implicit Schannel mapping, no bind :white_check_mark:
- [x] StartTLS (389) — SASL EXTERNAL bind :white_check_mark:
- [x] TLS 1.2 enforced for legacy DC compatibility :white_check_mark:
- [x] Defensive whoami (no panic on empty mapping) :white_check_mark:
- [ ] Automatic transport fallback (try StartTLS, retry LDAPS on failure) :red_circle:
- [ ] Robust PKCS#12 for modern Certipy PFX (AES/SHA-2 MAC) :red_circle:

## Implemented actions

- [x] `whoami` :white_check_mark:
- [x] `ldapshell` (search / dn / whoami) :white_check_mark:
- [x] `add_computer` / `del_computer` :white_check_mark:
- [x] `modify_user` — password reset :white_check_mark:
- [x] `modify_user --elevate` — grant DCSync (DS-Replication-Get-Changes*) :white_check_mark:
- [x] `add_member` / `remove_member` (group membership) :white_check_mark:
- [x] `enable_account` / `disable_account` (UAC ACCOUNTDISABLE) :white_check_mark:
- [x] `read_rbcd` / `write_rbcd` / `remove_rbcd` / `flush_rbcd` :white_check_mark:

## Planned actions

### Credential recovery
- [ ] `read_laps` — read LAPS v1 password (`ms-Mcs-AdmPwd`) :red_circle:
- [ ] `read_laps2` — read LAPS v2 (`msLAPS-Password` / `msLAPS-EncryptedPassword`, DPAPI-NG decrypt) :red_circle:
- [ ] `read_gmsa` — read gMSA managed password blob (`msDS-ManagedPassword`) and derive the NT hash :red_circle:

### Account / object manipulation
- [ ] `modify_user --remove-elevate` — revoke DCSync (restore the domain SD) :red_circle:
- [ ] `modify_computer` — reset a machine account password :red_circle:
- [ ] `add_spn` / `remove_spn` — write `servicePrincipalName` (targeted Kerberoast) :red_circle:
- [ ] `set_dontreqpreauth` — toggle DONT_REQ_PREAUTH for AS-REP roasting :red_circle:
- [ ] `set_owner` — change `nTSecurityDescriptor` owner (WriteOwner abuse) :red_circle:
- [ ] `write_dacl` — add a generic ACE on an arbitrary object :red_circle:

### Shadow Credentials (Key Trust)
- [x] `add_shadow_cred` — add a Key Credential (`msDS-KeyCredentialLink`) :white_check_mark:
- [x] `remove_shadow_cred` / `list_shadow_cred` :white_check_mark:

### Delegation
- [ ] Constrained delegation write (`msDS-AllowedToDelegateTo`) on add_computer :red_circle:
- [ ] Unconstrained delegation flag toggle (`TRUSTED_FOR_DELEGATION`) :red_circle:

## ldapshell improvements
- [x] Show attributes, not only DNs :white_check_mark:
- [x] Inline write commands (set_rbcd, add_member, elevate…) from the shell :white_check_mark:
- [x] Tab completion / history :white_check_mark: