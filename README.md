# sshhole-check

A read-only script that tells you whether a Linux host is affected by the
OpenSSH/musl password bypass described at <https://sshhole.com/>.

On musl libc, an OpenSSH `sshd` built without PAM accepts any password longer
than 256 bytes for accounts whose shadow password field is `*` (key-only or
locked accounts, such as root on Alpine).

## Usage

```sh
sudo sh check-sshhole.sh
```

The script changes nothing and never attempts a login. It works with POSIX sh
and busybox ash, so it runs on Alpine, Ubuntu, Debian and similar.

## Verdicts

| Exit code | Verdict |
|---|---|
| 0 | NOT AFFECTED |
| 1 | AFFECTED: musl, no PAM, passwords enabled, and an exposed account exists |
| 2 | INCONCLUSIVE: for example, not run as root |
| 3 | Vulnerable setup but no exposed account right now; update anyway |

It checks, in order: sshd installed, libc (glibc is not affected), OpenSSH
version, `UsePAM`, then accounts with `*` as password and a login shell,
including per-user `Match` overrides of `PasswordAuthentication`.

## Caveats

- The fixed version (OpenSSH 10.6p2) comes from the sshhole.com page and is not
  independently verified. Distros often backport fixes without changing the
  version string, so an older version on a patched package may still be reported
  as AFFECTED.
- `AllowUsers`, `DenyUsers` and `AllowGroups` are not evaluated, so the script
  can over-report.
- It shows whether the bug applies. It does not show whether a host was
  already compromised. Check your auth logs.
- Tested on Alpine 3.20 and Ubuntu 22.04 containers, not on every distro.

## License

MIT, see [LICENSE](LICENSE).
