#!/bin/sh
# check-sshhole.sh - read-only check for the "sshhole" bug (https://sshhole.com/):
# on musl libc, an OpenSSH sshd built without PAM accepts any password longer
# than 256 bytes for accounts whose shadow password field is "*".
#
# Usage:  sudo sh check-sshhole.sh
# Changes nothing and never attempts a login. Works with POSIX sh / busybox ash.
#
# Exit codes:
#   0  NOT AFFECTED
#   1  AFFECTED   (vulnerable setup and at least one exposed account)
#   2  INCONCLUSIVE (could not check everything; see message)
#   3  NOT EXPLOITABLE NOW, but vulnerable setup (musl, no PAM, passwords on)
#
# Fix threshold below comes from the sshhole.com page and is not independently
# verified. Distros often backport fixes without changing the version string.

FIXED_MAJOR=10; FIXED_MINOR=6; FIXED_PATCH=2

if [ -t 1 ]; then R='\033[31m'; G='\033[32m'; Y='\033[33m'; N='\033[0m'; else R=; G=; Y=; N=; fi

info() { printf '  %s\n' "$*"; }
finish() { # code colour label detail
    printf '\n%b==> %s%b\n' "$2" "$3" "$N"
    [ -n "$4" ] && printf '    %s\n' "$4"
    exit "$1"
}

printf 'sshhole check on %s (%s)\n\n' "$(hostname 2>/dev/null)" "$(uname -sr)"

# 1. Is OpenSSH sshd installed?
SSHD=$(command -v sshd 2>/dev/null)
if [ -z "$SSHD" ]; then
    for p in /usr/sbin/sshd /sbin/sshd /usr/local/sbin/sshd; do
        [ -x "$p" ] && SSHD=$p && break
    done
fi
if [ -z "$SSHD" ]; then
    info "sshd: not found"
    finish 0 "$G" "NOT AFFECTED" "No OpenSSH server is installed here (Dropbear and others are not affected)."
fi
info "sshd: $SSHD"

# 2. Which libc does sshd use?
libc_out="$(ldd "$SSHD" 2>&1; ldd --version 2>&1)"
case "$libc_out" in
    *musl*) libc=musl ;;
    *GLIBC*|*"GNU libc"*|*libc.so.6*) libc=glibc ;;
    *) libc=unknown ;;
esac
info "libc: $libc"
case $libc in
    glibc) finish 0 "$G" "NOT AFFECTED" "glibc systems are not affected by this bug." ;;
    unknown) finish 2 "$Y" "INCONCLUSIVE" "Could not determine the libc. Run 'ldd --version' and 'ldd $SSHD' and check for 'musl'." ;;
esac

# 3. OpenSSH version (informational unless clearly fixed)
ver_raw=$("$SSHD" -V 2>&1 | grep -o 'OpenSSH_[0-9.]*p[0-9]*' | head -n1)
[ -z "$ver_raw" ] && ver_raw=$(ssh -V 2>&1 | grep -o 'OpenSSH_[0-9.]*p[0-9]*' | head -n1)
if [ -n "$ver_raw" ]; then
    info "OpenSSH: $ver_raw"
    v=${ver_raw#OpenSSH_}
    maj=${v%%.*}; rest=${v#*.}; min=${rest%%p*}; pat=${rest#*p}
    if [ "$maj" -gt $FIXED_MAJOR ] 2>/dev/null ||
       { [ "$maj" -eq $FIXED_MAJOR ] && [ "$min" -gt $FIXED_MINOR ]; } 2>/dev/null ||
       { [ "$maj" -eq $FIXED_MAJOR ] && [ "$min" -eq $FIXED_MINOR ] && [ "$pat" -ge $FIXED_PATCH ]; } 2>/dev/null; then
        finish 0 "$G" "NOT AFFECTED" "OpenSSH $ver_raw is at or above the fixed release ${FIXED_MAJOR}.${FIXED_MINOR}p${FIXED_PATCH}."
    fi
else
    info "OpenSSH: version not detected"
fi

# 4. The rest needs root (sshd -T and the shadow file)
if [ "$(id -u)" != 0 ]; then
    finish 2 "$Y" "INCONCLUSIVE" "musl detected, but the config and shadow file need root. Re-run with: sudo sh $0"
fi

cfg=$("$SSHD" -T 2>&1) || finish 2 "$Y" "INCONCLUSIVE" "'sshd -T' failed: $(printf '%s' "$cfg" | head -n1)"
usepam=$(printf '%s\n' "$cfg" | awk '$1=="usepam"{print $2; exit}')
pwauth=$(printf '%s\n' "$cfg" | awk '$1=="passwordauthentication"{print $2; exit}')
[ -z "$usepam" ] && usepam=no  # sshd built without PAM omits the option from 'sshd -T'
info "UsePAM: $usepam"
info "PasswordAuthentication: $pwauth"

if [ "$usepam" = yes ]; then
    finish 0 "$G" "NOT AFFECTED" "sshd uses PAM, which is not affected."
fi

# 5. Accounts with "*" as password and a login shell
shadow=$(getent shadow 2>/dev/null)
[ -z "$shadow" ] && shadow=$(cat /etc/shadow 2>/dev/null)
[ -z "$shadow" ] && finish 2 "$Y" "INCONCLUSIVE" "Cannot read the shadow database."

exposed=
for u in $(printf '%s\n' "$shadow" | awk -F: '$2=="*"{print $1}'); do
    shell=$(getent passwd "$u" 2>/dev/null | cut -d: -f7)
    case "$shell" in
        */nologin|*/false|*/sync|*/halt|*/shutdown) continue ;;
    esac
    # Match blocks may re-enable passwords for a specific user
    ucfg=$("$SSHD" -T -C "user=$u,host=localhost,addr=127.0.0.1" 2>/dev/null) || ucfg=$cfg
    upw=$(printf '%s\n' "$ucfg" | awk '$1=="passwordauthentication"{print $2; exit}')
    if [ "$upw" = yes ]; then
        exposed="$exposed $u"
    fi
done

if [ -n "$exposed" ]; then
    info "key-only accounts reachable by password bypass:$exposed"
    finish 1 "$R" "AFFECTED" "musl + no PAM + passwords on + exposed account(s).
    Fix now: 'apk upgrade openssh' (or your distro's update), or disable passwords:
      echo 'PasswordAuthentication no' > /etc/ssh/sshd_config.d/10-nopw.conf
    then restart sshd. Review auth logs for logins you did not make; if any, treat the host as compromised.
    Note: AllowUsers/DenyUsers/AllowGroups limits were not evaluated."
fi

if [ "$pwauth" = yes ]; then
    finish 3 "$Y" "NOT EXPLOITABLE NOW (vulnerable setup)" "musl + no PAM + passwords on, but no '*' account with a login shell exists. Update OpenSSH anyway; adding a key-only user would expose you."
fi

finish 0 "$G" "NOT AFFECTED" "Password authentication is disabled."
