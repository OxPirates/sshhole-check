# sshhole-check

A read-only script that tells you whether a Linux host is affected by the
OpenSSH/musl password bypass described at <https://sshhole.com/> and reported
as **CVE-2026-123158** (unconfirmed — see [CVE status](#cve-status)).

## The bug

On musl libc, `crypt()` returns the string `*` when a password is too long to
hash (SHA-512 crypt in musl caps at 256 bytes). `*` is also the marker musl
uses for a locked or key-only account's password field in `/etc/shadow`. An
OpenSSH `sshd` built **without PAM** compares the two strings directly, so a
password longer than 256 bytes matches a `*` account and logs in — no
credentials needed.

Confirmed by the [OpenSSH 10.6p2 release notes](https://www.openssh.org/releasenotes.html)
(2026-11-05): "avoid password authentication bypass that is exploitable
through sshd(8)", affecting Linux systems using musl libc with PAM disabled.
OpenSSH states the root cause is outside sshd but exploitable via it. Reported
by Özgün Kültekin of Wakefield.

## Who is affected

All of these must be true:

- **musl libc** — Alpine, OpenWrt, Buildroot, Yocto, many minimal Docker images.
  glibc systems (Ubuntu, Debian, RHEL/Rocky/Fedora, Arch, openSUSE, …) are not
  affected regardless of the rest.
- **sshd without PAM** — Alpine's default `openssh-server` package, or any
  build with `UsePAM no`. Alpine's separate `openssh-server-pam` package
  (`UsePAM yes`) is not affected.
- **`PasswordAuthentication yes`** — the OpenSSH default.
- **At least one account with `*` as its shadow password field, and a real
  login shell** (not `/sbin/nologin` etc.) — see the two cases below.
- **OpenSSH older than 10.6p2.**

### "All my accounts have a real password set" — am I affected?

**No, not in practice**, even on an otherwise-vulnerable host. The bypass only
fires when sshd compares the oversized password against a shadow field that
is literally `*`. A real hash (`$5$...`, `$6$...`) never equals `*`, so a long
password just fails like any wrong password would — there's no account for
the trick to land on.

Patch anyway, and double-check **root** specifically: some minimal images
leave root's shadow field as `*` even when every interactive account has a
real password. Adding one key-only, locked, or LDAP-backed account later
re-opens the exposure.

### "I log in with an SSH key, not a password" — am I affected?

**This is the exposed case, not a safe one.** A key-only account is set up
*without* a password, which is exactly what leaves its shadow field at `*`.
Your key still works fine, but if `PasswordAuthentication yes` is set
anywhere on a vulnerable host, an attacker doesn't need your key at all — they
can send any password over 256 bytes to that same account and get in via the
musl `crypt()` match. Using keys yourself does not protect the account; the
server-side setting does.

If you only ever intend to log in with keys, the durable fix is to turn
password authentication off entirely, not just to patch OpenSSH:

```sh
echo "PasswordAuthentication no" > /etc/ssh/sshd_config.d/10-nopw.conf
```

That removes the password path a long password would walk through, on any
OpenSSH version.

## Usage

```sh
sudo sh check-sshhole.sh
```

The script changes nothing and never attempts a login — it only reads local
config and the shadow file, and briefly generates a throwaway SSH host key in
a temp directory (deleted on exit) if sshd has none, just so `sshd -T` can run.
It works with POSIX sh and busybox ash, so it runs on Alpine, Ubuntu, Debian
and similar.

**This is a local detection check, not a remote exploit test.** It never
sends a password over the network to see if a login succeeds — that would be
an actual authentication-bypass attempt, not a safe check, even against your
own host.

## Verdicts

| Exit code | Verdict |
|---|---|
| 0 | NOT AFFECTED |
| 1 | AFFECTED: musl, no PAM, passwords enabled, and an exposed account exists |
| 2 | INCONCLUSIVE: for example, not run as root |
| 3 | Vulnerable setup but no exposed account right now; update anyway |

It checks, in order: sshd installed and which binary is actually running
(Alpine ships a separate `sshd.pam`), libc (glibc is not affected), OpenSSH
version against the 10.6p2 fix, `UsePAM`, then accounts with `*` as password
and a login shell, including per-user `Match` overrides of
`PasswordAuthentication`.

## CVE status

Multiple outlets ([IONIX](https://www.ionix.io/threat-center/cve-2026-123158/),
[OX Security](https://www.ox.security/blog/openssh-authentication-bypass-cve-2026-123158/))
report this as **CVE-2026-123158**, CVSS 3.1 **8.1 High**
(`AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H`). Neither the OpenSSH release notes nor
sshhole.com name a CVE, and [Orca Security](https://orca.security/resources/research/sshole-openssh-authentication-bypass-gives-attackers-root-on-alpine-linux/)
reported no CVE assigned as of their publication. Verify the ID on
[nvd.nist.gov](https://nvd.nist.gov/) or [cve.org](https://www.cve.org/) before
citing it in anything formal.

## Caveats

- The fixed version (OpenSSH 10.6p2) is confirmed by the official OpenSSH
  release notes. Distros can still backport the fix without changing the
  version string, so an older version on an already-patched package may be
  reported as AFFECTED.
- `AllowUsers`, `DenyUsers` and `AllowGroups` are not evaluated, so the script
  can over-report.
- It shows whether the bug applies. It does not show whether a host was
  already compromised — check your auth logs for unexpected logins to
  key-only or locked accounts.
- Tested in containers on Alpine 3.20 (with and without PAM, with and without
  `ldd`/`getent`), Debian 12, Ubuntu 20.04/22.04/24.04, Rocky 9, Fedora, Arch
  and openSUSE Leap 15. Not tested on real OpenWrt or Void-musl hosts.

## License

MIT, see [LICENSE](LICENSE).
