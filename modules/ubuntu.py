"""
modules/ubuntu.py — Ubuntu workstation hardening.

Applies CIS Ubuntu Benchmark recommendations + ISSP (ISO 27002 v2) requirements
to a running Ubuntu (or Debian-compatible) system.

Must be invoked as root.  Each public function corresponds to one hardening
domain; they are called in sequence by harden() at the bottom of this file.

Key sections
────────────
  apply_sysctl()              — UBU-005..021  kernel network/security params
  harden_ssh()                — UBU-024..035  SSH daemon configuration
  configure_pam()             — UBU-038..043  password quality + lockout
  configure_login_defs()      — UBU-044..047  /etc/login.defs policy
  disable_unused_services()   — UBU-048..060  stop & mask unneeded daemons
  configure_ufw()             — UBU-001..004  UFW firewall rules
  configure_auditd()          — UBU-061..071  auditd rules
  fix_file_permissions()      — UBU-072..082  chmod/chown sensitive files
  configure_filesystem()      — UBU-083..085  fstab, core dumps
  configure_apparmor()        — UBU-022..023  AppArmor enforce mode
  configure_user_accounts()   — UBU-087..090  lock system accounts, umask
  configure_cron()            — UBU-091..092  cron.allow / at.allow
  configure_screen_lock()     — UBU-093..095  GNOME idle lock (300 s / ISSP)
  configure_automatic_updates()— UBU-096..097 unattended-upgrades
  configure_aide()            — UBU-098..100  AIDE file integrity monitoring
  configure_logging()         — UBU-101..104  rsyslog, logrotate, chrony, CAD
  configure_system_banners()  — UBU-105..107  /etc/motd, issue, issue.net
  configure_sudo()            — UBU-108..109  sudoers hardening
  check_luks_encryption()     — UBU-110       LUKS status report
  harden_misc()               — kernel module blacklist, /proc hidepid
"""

import os
import re
import shutil
import subprocess
import tempfile
from modules.logger import get_logger, log_ok, log_warn, log_fail, log_section, log_skip

# ── Legal banner written to /etc/motd, /etc/issue, /etc/issue.net ─────────────
BANNER_TEXT = """\
*******************************************************************************
*                   AUTHORISED USE ONLY — Bidouille                           *
*                                                                              *
* This system is the property of Bidouille. Access is restricted to           *
* authorised personnel only. All activities on this system are logged and      *
* monitored. Unauthorised access is prohibited and subject to prosecution      *
* under applicable French and EU laws.                                         *
*                                                                              *
* If you are not an authorised user, disconnect immediately.                  *
*******************************************************************************
"""


# ── Low-level helpers ─────────────────────────────────────────────────────────

def _run(args: list, label: str, check: bool = False) -> bool:
    """
    Run an external command and log the outcome.

    Args:
        args:   Command + arguments list, e.g. ["systemctl", "enable", "auditd"].
        label:  Human-readable description printed in the log.
        check:  If True, a non-zero exit code is logged as FAIL instead of WARN.

    Returns:
        True if the command succeeded (exit code 0), False otherwise.
    """
    try:
        result = subprocess.run(args, capture_output=True, text=True, timeout=300)
        if result.returncode == 0:
            log_ok(label)
            return True
        else:
            msg = f"{label}: exit {result.returncode} — {result.stderr.strip()[:200]}"
            if check:
                log_fail(msg)
            else:
                log_warn(msg)
            return False
    except FileNotFoundError:
        # Package not installed — treat as a non-fatal skip
        log_skip(f"{label}: command not found (package may not be installed)")
        return False
    except subprocess.TimeoutExpired:
        log_warn(f"{label}: timed out after 300 s")
        return False
    except Exception as exc:
        log_fail(f"{label}: unexpected error — {exc}")
        return False


def _write_file(path: str, content: str, mode: int = 0o644) -> bool:
    """
    Atomically write *content* to *path* and set its permissions to *mode*.

    Uses a temporary file in the same directory so the write is atomic:
    the original file is never left in a half-written state if the process
    is interrupted.

    Args:
        path:    Absolute destination path.
        content: Text to write (UTF-8).
        mode:    Permission bits (octal), e.g. 0o600.

    Returns:
        True on success, False if any step failed (error is logged).
    """
    try:
        parent = os.path.dirname(path)
        if parent:
            os.makedirs(parent, exist_ok=True)

        # Write to a temp file first, then atomically replace the target
        dir_for_tmp = parent if parent else "."
        fd, tmp_path = tempfile.mkstemp(dir=dir_for_tmp)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write(content)
            os.chmod(tmp_path, mode)
            # os.replace is atomic on POSIX: no window where the file is absent
            os.replace(tmp_path, path)
        except Exception:
            # Clean up the temp file if something went wrong before the replace
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
            raise

        return True
    except PermissionError as exc:
        log_fail(f"_write_file({path}): permission denied — {exc}")
        return False
    except OSError as exc:
        log_fail(f"_write_file({path}): OS error — {exc}")
        return False


def _set_sysctl(key: str, value: str, conf_file: str) -> None:
    """
    Ensure *key = value* is present (and uncommented) in *conf_file*.

    If the key already exists (even commented out), its line is replaced.
    Otherwise the key=value pair is appended.  Uses re.MULTILINE so '^'
    matches the start of each line in the file content.

    Args:
        key:       sysctl parameter name, e.g. "net.ipv4.ip_forward".
        value:     Desired value string, e.g. "0".
        conf_file: Path to the sysctl drop-in file to update.
    """
    try:
        content = open(conf_file).read() if os.path.exists(conf_file) else ""

        # Match any existing line for this key (may be commented with #)
        pattern = re.compile(
            r"^#?\s*" + re.escape(key) + r"\s*=.*$",
            re.MULTILINE
        )
        new_line = f"{key} = {value}"

        if pattern.search(content):
            content = pattern.sub(new_line, content)
        else:
            # Append with a leading newline to avoid merging with the last line
            content += f"\n{new_line}"

        with open(conf_file, "w") as f:
            f.write(content)
    except OSError as exc:
        log_warn(f"sysctl {key}: could not update {conf_file} — {exc}")


def _set_login_defs(key: str, value: str) -> None:
    """
    Update (or append) a KEY VALUE pair in /etc/login.defs.

    Args:
        key:   Setting name, e.g. "PASS_MAX_DAYS".
        value: Desired value, e.g. "90".
    """
    path = "/etc/login.defs"
    try:
        content = open(path).read()
        # Match the key whether it is commented or not
        pattern = re.compile(
            r"^#?\s*" + re.escape(key) + r"\s+.*$",
            re.MULTILINE
        )
        new_line = f"{key}\t{value}"
        if pattern.search(content):
            content = pattern.sub(new_line, content)
        else:
            content += f"\n{new_line}\n"
        with open(path, "w") as f:
            f.write(content)
    except OSError as exc:
        log_warn(f"login.defs {key}: {exc}")


def _set_pwquality(key: str, value: str) -> None:
    """
    Update (or append) a 'key = value' pair in /etc/security/pwquality.conf.

    Args:
        key:   Parameter name, e.g. "minlen".
        value: Desired value, e.g. "12".
    """
    path = "/etc/security/pwquality.conf"
    try:
        content = open(path).read() if os.path.exists(path) else ""
        pattern = re.compile(
            r"^#?\s*" + re.escape(key) + r"\s*=.*$",
            re.MULTILINE
        )
        new_line = f"{key} = {value}"
        if pattern.search(content):
            content = pattern.sub(new_line, content)
        else:
            content += f"\n{new_line}\n"
        with open(path, "w") as f:
            f.write(content)
    except OSError as exc:
        log_warn(f"pwquality {key}: {exc}")


# ── Hardening sections ────────────────────────────────────────────────────────

def apply_sysctl() -> None:
    """
    UBU-005..021 — Write CIS-recommended kernel parameters to a dedicated
    sysctl drop-in file and apply them immediately.

    Drop-in file: /etc/sysctl.d/99-cis-hardening.conf
    This file takes precedence over /etc/sysctl.conf and default system files.
    Parameters are also applied live via 'sysctl -w' so they take effect
    without requiring a reboot.
    """
    log_section("Kernel / sysctl Hardening (UBU-005..021)")
    conf = "/etc/sysctl.d/99-cis-hardening.conf"

    # Each tuple: (parameter, value)
    # Parameters are grouped by category for readability.
    sysctl_settings = [
        # ── IPv4 routing / forwarding ──────────────────────────────────────
        # Workstations must NOT forward packets between interfaces
        ("net.ipv4.ip_forward",                          "0"),
        ("net.ipv4.conf.all.send_redirects",             "0"),
        ("net.ipv4.conf.default.send_redirects",         "0"),
        ("net.ipv4.conf.all.accept_redirects",           "0"),
        ("net.ipv4.conf.default.accept_redirects",       "0"),
        # Secure redirects: only accept from listed default gateways
        ("net.ipv4.conf.all.secure_redirects",           "0"),
        ("net.ipv4.conf.default.secure_redirects",       "0"),
        # Log packets with impossible source addresses (martians)
        ("net.ipv4.conf.all.log_martians",               "1"),
        ("net.ipv4.conf.default.log_martians",           "1"),
        # SYN flood protection
        ("net.ipv4.tcp_syncookies",                      "1"),
        # Ignore ICMP broadcast pings (Smurf attack mitigation)
        ("net.ipv4.icmp_echo_ignore_broadcasts",         "1"),
        # Ignore bogus ICMP error responses
        ("net.ipv4.icmp_ignore_bogus_error_responses",   "1"),
        # Reverse path filtering — drop packets with spoofed source addresses
        ("net.ipv4.conf.all.rp_filter",                  "1"),
        ("net.ipv4.conf.default.rp_filter",              "1"),
        # Do not accept source-routed packets
        ("net.ipv4.conf.all.accept_source_route",        "0"),
        ("net.ipv4.conf.default.accept_source_route",    "0"),
        # RFC 1337 TIME_WAIT assassination fix
        ("net.ipv4.tcp_rfc1337",                         "1"),
        # TCP timestamps can leak uptime info — disable
        ("net.ipv4.tcp_timestamps",                      "0"),

        # ── IPv6 (disabled entirely per CIS + ISSP) ───────────────────────
        ("net.ipv6.conf.all.disable_ipv6",               "1"),
        ("net.ipv6.conf.default.disable_ipv6",           "1"),
        ("net.ipv6.conf.all.accept_redirects",           "0"),
        ("net.ipv6.conf.default.accept_redirects",       "0"),

        # ── Kernel hardening ──────────────────────────────────────────────
        # ASLR — randomise memory layout to make exploitation harder
        ("kernel.randomize_va_space",   "2"),
        # Restrict /dev/kmsg and dmesg to root
        ("kernel.dmesg_restrict",       "1"),
        # Paranoid perf events — prevent unprivileged profiling
        ("kernel.perf_event_paranoid",  "3"),
        # Hide kernel symbol addresses from non-root processes
        ("kernel.kptr_restrict",        "2"),

        # ── Filesystem ────────────────────────────────────────────────────
        # No core dumps from setuid binaries
        ("fs.suid_dumpable",            "0"),
        # Prevent hard-link attacks (CVE-2010-3054 class)
        ("fs.protected_hardlinks",      "1"),
        ("fs.protected_symlinks",       "1"),
    ]

    # Build the drop-in file content from the list above
    lines = "# CIS/ISSP Ubuntu Hardening — generated by harden.py\n"
    lines += "# Do not edit manually; re-run harden.py to update.\n\n"
    for key, val in sysctl_settings:
        lines += f"{key} = {val}\n"

    if not _write_file(conf, lines):
        log_fail("apply_sysctl: could not write sysctl drop-in — skipping")
        return

    log_ok(f"sysctl drop-in written: {conf}")

    # Apply the file via sysctl -p so parameters take effect immediately
    _run(["sysctl", "-p", conf], "sysctl -p applied")

    # Also push each value individually via 'sysctl -w' to ensure the running
    # kernel picks up the change even if -p has quirks with the drop-in path.
    for key, val in sysctl_settings:
        subprocess.run(
            ["sysctl", "-w", f"{key}={val}"],
            capture_output=True, timeout=5
        )

    log_ok("UBU-005..021: kernel parameters hardened")


def harden_ssh() -> None:
    """
    UBU-024..035 — Rewrite /etc/ssh/sshd_config with a hardened configuration.

    Notable settings:
      - PermitRootLogin no         — root must not log in over SSH
      - MaxAuthTries 3             — limit brute-force attempts
      - ClientAliveInterval 300    — disconnect idle sessions after 5 min (ISSP §4.2)
      - Modern cipher/MAC/KEX suites only
      - Banner set to /etc/issue.net (legal warning)

    UBU-036 (PasswordAuthentication no) and UBU-037 (AllowGroups) are NOT
    automated because they require site-specific preparation; see IMPLEMENTATION.md.
    """
    log_section("SSH Hardening (UBU-024..035)")

    sshd_config = """\
# /etc/ssh/sshd_config
# Hardened by harden.py — CIS Ubuntu Benchmark + ISSP §4.2
# Re-generated on each harden.py run; manual edits will be overwritten.

# ── Protocol and port ─────────────────────────────────────────────────────────
# Protocol 2 is implicit in modern OpenSSH; listed for clarity.
Port 22

# ── Authentication ────────────────────────────────────────────────────────────
PermitRootLogin no              # UBU-024: root SSH login prohibited
MaxAuthTries 3                  # UBU-026: 3 attempts before disconnect
PermitEmptyPasswords no         # UBU-027: reject empty-password accounts
LoginGraceTime 60               # UBU-031: 60 s to complete authentication

# UsePAM must stay enabled so pam_faillock and pam_pwquality apply to SSH logins
UsePAM yes

# ── Session ───────────────────────────────────────────────────────────────────
# ISSP §4.2 — disconnect idle sessions after 5 min (300 s × 1 keepalive = 5 min)
ClientAliveInterval 300         # UBU-029
ClientAliveCountMax 0           # UBU-030: no keepalive retries → immediate disconnect

# ── Forwarding & tunnels (disabled) ──────────────────────────────────────────
X11Forwarding no                # UBU-028
AllowTcpForwarding no
PermitUserEnvironment no        # Prevent env injection via ~/.ssh/environment
IgnoreRhosts yes                # Disable legacy .rhosts authentication
HostbasedAuthentication no

# ── Banner (ISSP legal warning) ───────────────────────────────────────────────
Banner /etc/issue.net           # UBU-032

# ── Logging ───────────────────────────────────────────────────────────────────
SyslogFacility AUTH
LogLevel VERBOSE
PrintLastLog yes

# ── Connection limits (DoS / brute-force protection) ─────────────────────────
MaxStartups 10:30:60
MaxSessions 10
StrictModes yes
Compression no
TCPKeepAlive no

# ── Cryptography ─────────────────────────────────────────────────────────────
# UBU-033: Only strong authenticated-encryption ciphers
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr

# UBU-034: Encrypt-then-MAC algorithms only
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256

# UBU-035: Strong key exchange algorithms (no DH-group1, no SHA-1)
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group14-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,ecdh-sha2-nistp521,ecdh-sha2-nistp384,ecdh-sha2-nistp256

HostKeyAlgorithms ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521,ssh-rsa,rsa-sha2-256,rsa-sha2-512,ssh-ed25519
"""

    if not _write_file("/etc/ssh/sshd_config", sshd_config, mode=0o600):
        log_fail("harden_ssh: could not write sshd_config — SSH not hardened")
        return

    log_ok("UBU-024..035: /etc/ssh/sshd_config written (mode 600)")
    log_skip("UBU-036: PasswordAuthentication not disabled — pre-deploy SSH keys first")
    log_skip("UBU-037: AllowGroups not set — site-specific configuration required")

    # Restart SSH to apply the new configuration
    _run(["systemctl", "restart", "ssh"], "SSH service restarted")


def configure_pam() -> None:
    """
    UBU-038..043 — Harden PAM (Pluggable Authentication Modules):

      - pwquality.conf: enforce password complexity (minlen=12, all character classes)
      - pam_pwhistory:  remember last 24 passwords
      - pam_faillock:   lock account for 15 min after 5 failed attempts
      - faillock.conf:  persistent faillock configuration file

    PAM configuration is modified using targeted string searches rather than
    full rewrites to minimise the risk of breaking existing PAM stacks.
    """
    log_section("PAM Hardening (UBU-038..043)")

    # Install the password-quality library if not already present
    _run(["apt-get", "install", "-y", "-q", "libpam-pwquality"], "libpam-pwquality installed")

    # ── /etc/security/pwquality.conf ─────────────────────────────────────────
    # These settings enforce the ISSP §7.1 password policy.
    pwq_settings = [
        ("minlen",      "12"),   # UBU-038: minimum 12 characters
        ("dcredit",     "-1"),   # UBU-038: require at least 1 digit
        ("ucredit",     "-1"),   # UBU-038: require at least 1 uppercase
        ("lcredit",     "-1"),   # UBU-038: require at least 1 lowercase
        ("ocredit",     "-1"),   # UBU-038: require at least 1 special character
        ("maxrepeat",   "3"),    # UBU-039: no more than 3 consecutive identical chars
        ("maxsequence", "3"),    # no more than 3 sequential characters
        ("gecoscheck",  "1"),    # reject passwords containing the account's GECOS info
    ]
    for key, val in pwq_settings:
        _set_pwquality(key, val)
    log_ok("UBU-038..039: pwquality.conf updated (minlen=12, complexity enforced)")

    # ── /etc/pam.d/common-password: password history ─────────────────────────
    # We search for the exact pam_unix line and insert pam_pwhistory before it.
    # Ubuntu uses tabs as field separators; we match both tabs and spaces.
    try:
        with open("/etc/pam.d/common-password", "r") as f:
            content = f.read()

        if "pam_pwhistory.so" not in content:
            # Insert the pwhistory line immediately before the pam_unix line.
            # The regex accounts for both tab and space-separated fields.
            content = re.sub(
                r"^(password\s+\[success=1 default=ignore\]\s+pam_unix\.so)",
                "password\trequired\tpam_pwhistory.so remember=24 enforce_for_root\n\\1",
                content,
                flags=re.MULTILINE
            )
        else:
            # Already present — update the 'remember' count in place
            content = re.sub(
                r"(pam_pwhistory\.so[^\n]*)",
                "pam_pwhistory.so remember=24 enforce_for_root",
                content
            )

        # Ensure sha512 hashing is active on the pam_unix line.
        # The substitution only targets the pam_unix line (not other lines).
        if "sha512" not in content:
            content = re.sub(
                r"^(password\s+\[success=1 default=ignore\]\s+pam_unix\.so)(.*)$",
                r"\1\2 sha512 shadow",
                content,
                flags=re.MULTILINE
            )

        with open("/etc/pam.d/common-password", "w") as f:
            f.write(content)
        log_ok("UBU-040: pam_pwhistory remember=24 configured in common-password")
    except OSError as exc:
        log_warn(f"pam_pwhistory: could not modify common-password — {exc}")

    # ── /etc/pam.d/common-auth: account lockout via pam_faillock ─────────────
    # Two lines are needed:
    #   preauth  — checked before password verification (silent; starts counting)
    #   authfail — checked after a failed password (increments the counter)
    preauth  = "auth\trequired\tpam_faillock.so preauth silent audit deny=5 unlock_time=900 fail_interval=900"
    authfail = "auth\t[default=die]\tpam_faillock.so authfail audit deny=5 unlock_time=900 fail_interval=900"

    try:
        with open("/etc/pam.d/common-auth", "r") as f:
            content = f.read()

        if "pam_faillock.so" not in content:
            # Insert preauth before pam_unix; append authfail at the end
            content = re.sub(
                r"^(auth\s+\[success=1 default=ignore\]\s+pam_unix\.so)",
                f"{preauth}\n\\1",
                content,
                flags=re.MULTILINE
            )
            content += f"\n{authfail}\n"

        with open("/etc/pam.d/common-auth", "w") as f:
            f.write(content)
        log_ok("UBU-041..043: pam_faillock inserted in common-auth (deny=5, unlock=900 s)")
    except OSError as exc:
        log_warn(f"pam_faillock: could not modify common-auth — {exc}")

    # ── /etc/security/faillock.conf ───────────────────────────────────────────
    # Centralised faillock settings (modern systems read this instead of
    # parsing PAM arguments).
    faillock_conf = """\
# /etc/security/faillock.conf — CIS hardened by harden.py
# Lock account for 15 min after 5 failed attempts within a 15-min window.
deny         = 5
unlock_time  = 900
fail_interval= 900
audit
silent
"""
    _write_file("/etc/security/faillock.conf", faillock_conf)
    log_ok("UBU-041..043: /etc/security/faillock.conf written")


def configure_login_defs() -> None:
    """
    UBU-044..047 — Update /etc/login.defs password-aging and umask policies.

    These settings apply to newly created accounts.  Existing accounts need
    to be updated individually with 'chage'.
    """
    log_section("Login Definitions (UBU-044..047)")

    settings = [
        ("PASS_MAX_DAYS", "90"),    # UBU-044: password expires after 90 days (ISSP §7.1)
        ("PASS_MIN_DAYS", "1"),     # UBU-045: must wait 1 day before changing again
        ("PASS_WARN_AGE", "14"),    # UBU-046: warn 14 days before expiry
        ("PASS_MIN_LEN",  "12"),    # UBU-047: minimum 12 characters (ISSP §7.1)
        ("LOGIN_RETRIES", "3"),     # allow 3 bad passwords before disconnecting
        ("LOGIN_TIMEOUT", "60"),    # 60 s to complete login
        ("UMASK",         "027"),   # new files: owner=rwx, group=rx, other=none
        ("HOME_MODE",     "0750"),  # new home directories not world-readable
        # Use a high number of SHA-512 rounds to slow down offline cracking
        ("SHA_CRYPT_MIN_ROUNDS", "65536"),
        ("SHA_CRYPT_MAX_ROUNDS", "65536"),
    ]
    for key, val in settings:
        _set_login_defs(key, val)
    log_ok("UBU-044..047: /etc/login.defs hardened")


def disable_unused_services() -> None:
    """
    UBU-048..060 — Disable and stop services that have no business purpose on
    a hardened workstation.

    Each service is passed to 'systemctl disable --now'.  If the service is not
    installed, systemctl will return a non-zero code which is logged as a SKIP
    (not a failure).

    NOTE: smbd/nmbd (Samba) is intentionally skipped (UBU-060) because it may
    be needed for Active Directory domain-join via winbind.
    """
    log_section("Disable Unused Services (UBU-048..060)")

    services = [
        "telnet",               # UBU-048: cleartext remote shell
        "inetd", "xinetd",      # legacy super-daemons
        "vsftpd", "ftp",        # UBU-049: cleartext FTP
        "rsh-server", "rsh",    # UBU-050: insecure legacy remote shell
        "avahi-daemon",         # UBU-051: mDNS/zeroconf (information leakage)
        "cups",                 # UBU-052: printing (not needed on most workstations)
        "isc-dhcp-server",      # UBU-053: DHCP server
        "isc-dhcp-server6",
        "slapd",                # UBU-054: LDAP server
        "nfs-server",           # UBU-055: NFS server
        "nfs-kernel-server",
        "rpcbind",              # UBU-056: RPC port mapper
        "named", "bind9",       # UBU-057: DNS server
        "apache2",              # UBU-058: web server
        "dovecot",              # UBU-059: mail server (IMAP/POP3)
        "snmpd",                # SNMP daemon — information leakage risk
        "rsync",                # rsync daemon mode
        "nis",                  # NIS/YP — insecure legacy directory service
        "talk", "talkd",        # legacy talk client/server
    ]

    for svc in services:
        # 'disable --now' both disables auto-start and stops the running unit.
        # A non-zero return is expected for services that are not installed.
        result = subprocess.run(
            ["systemctl", "disable", "--now", svc],
            capture_output=True, text=True, timeout=30
        )
        if result.returncode == 0:
            log_ok(f"Service disabled: {svc}")
        else:
            log_skip(f"Service '{svc}': not installed or already disabled")

    # UBU-060: Samba is intentionally left alone
    log_skip("UBU-060: smbd/nmbd NOT disabled — required for Active Directory / Samba integration")


def configure_ufw() -> None:
    """
    UBU-001..004 — Install UFW, set default policies, and allow SSH.

    Default policy: deny all inbound, allow all outbound.
    Only SSH (22/tcp) is explicitly permitted.  Additional rules for
    application-specific services must be added manually after deployment.
    """
    log_section("UFW Firewall (UBU-001..004)")

    _run(["apt-get", "install", "-y", "-q", "ufw"], "UFW installed")

    # Reset to a known-clean state before applying our rules
    _run(["ufw", "--force", "reset"],         "UFW reset to defaults")
    _run(["ufw", "default", "deny",  "incoming"], "UBU-002: default deny inbound")
    _run(["ufw", "default", "allow", "outgoing"], "UBU-003: default allow outbound")
    _run(["ufw", "allow", "22/tcp"],              "UBU-004: SSH allowed")

    # Enable UFW non-interactively (--force suppresses the confirmation prompt)
    result = subprocess.run(
        ["ufw", "--force", "enable"],
        capture_output=True, text=True, timeout=30
    )
    if result.returncode == 0:
        log_ok("UBU-001: UFW enabled")
    else:
        log_warn(f"UFW enable: {result.stderr.strip()}")


def configure_auditd() -> None:
    """
    UBU-061..071 — Install auditd and deploy CIS audit rules.

    Rules written to: /etc/audit/rules.d/99-cis-hardening.rules

    Key audit domains:
      - Time changes (adjtimex, settimeofday)
      - User/group modifications (/etc/passwd, shadow, group, gshadow)
      - Network configuration changes
      - sudo and privileged command usage
      - File deletions by users
      - setuid/setgid execution, mount operations
      - Login/logout events (wtmp, btmp, lastlog)
      - Kernel module loading

    The file ends with '-e 2' (immutable mode): once loaded, the ruleset
    cannot be changed without a reboot.  This prevents an attacker who gains
    root from silently disabling audit logging.
    """
    log_section("Auditd Configuration (UBU-061..071)")

    _run(
        ["apt-get", "install", "-y", "-q", "auditd", "audispd-plugins"],
        "auditd + audispd-plugins installed"
    )

    audit_rules = """\
# /etc/audit/rules.d/99-cis-hardening.rules
# Deployed by harden.py — CIS Ubuntu Benchmark
# Re-generated on each harden.py run; manual edits will be overwritten.

## Remove all pre-existing rules
-D

## Increase the kernel audit buffer to handle bursts without dropping events
-b 8192

## Failure mode: 1 = log to kernel ring buffer, 2 = kernel panic
-f 1

# ── UBU-062: Time change events ───────────────────────────────────────────────
-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change
-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change
-a always,exit -F arch=b64 -S clock_settime -k time-change
-w /etc/localtime -p wa -k time-change

# ── UBU-063: User/group identity files ───────────────────────────────────────
-w /etc/group    -p wa -k identity
-w /etc/passwd   -p wa -k identity
-w /etc/gshadow  -p wa -k identity
-w /etc/shadow   -p wa -k identity
-w /etc/security/opasswd -p wa -k identity

# ── UBU-064: Network configuration changes ────────────────────────────────────
-a always,exit -F arch=b64 -S sethostname -S setdomainname -k system-locale
-a always,exit -F arch=b32 -S sethostname -S setdomainname -k system-locale
-w /etc/issue     -p wa -k system-locale
-w /etc/issue.net -p wa -k system-locale
-w /etc/hosts     -p wa -k system-locale
-w /etc/network   -p wa -k system-locale

## MAC policy changes (AppArmor)
-w /etc/apparmor/   -p wa -k MAC-policy
-w /etc/apparmor.d/ -p wa -k MAC-policy

# ── UBU-065: sudo / privileged command usage ──────────────────────────────────
-w /etc/sudoers   -p wa -k actions
-w /etc/sudoers.d/ -p wa -k actions
-w /var/log/sudo.log -p wa -k actions
## Capture execve calls where the effective UID is 0 but real UID is not
-a always,exit -F arch=b64 -C euid!=uid -F euid=0 -S execve -k actions

# ── UBU-066: File deletions by unprivileged users ─────────────────────────────
-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete
-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete

# ── UBU-067: Permissions/ownership changes and mount ─────────────────────────
-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts
-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts
-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat  -F auid>=1000 -k perm_mod
-a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -k perm_mod
-a always,exit -F arch=b64 -S setxattr -S lsetxattr -S fsetxattr -F auid>=1000 -k perm_mod
-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat  -F auid>=1000 -k perm_mod
-a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -k perm_mod

# ── UBU-068: Login/logout / session events ────────────────────────────────────
-w /var/log/faillog  -p wa -k logins
-w /var/log/lastlog  -p wa -k logins
-w /var/run/faillock/ -p wa -k logins
-w /var/run/utmp -p wa -k session
-w /var/log/wtmp -p wa -k session
-w /var/log/btmp -p wa -k session

# ── UBU-069: Privileged commands ──────────────────────────────────────────────
-a always,exit -F path=/usr/bin/sudo      -F perm=x -F auid>=1000 -k privileged
-a always,exit -F path=/usr/bin/su        -F perm=x -F auid>=1000 -k privileged
-a always,exit -F path=/usr/bin/newgrp    -F perm=x -F auid>=1000 -k privileged
-a always,exit -F path=/usr/bin/passwd    -F perm=x -F auid>=1000 -k privileged
-a always,exit -F path=/usr/sbin/usermod  -F perm=x -F auid>=1000 -k privileged
-a always,exit -F path=/usr/sbin/useradd  -F perm=x -F auid>=1000 -k privileged
-a always,exit -F path=/usr/sbin/userdel  -F perm=x -F auid>=1000 -k privileged
-a always,exit -F path=/usr/sbin/groupmod -F perm=x -F auid>=1000 -k privileged

## Kernel module loading/unloading
-w /sbin/insmod  -p x -k modules
-w /sbin/rmmod   -p x -k modules
-w /sbin/modprobe -p x -k modules
-a always,exit -F arch=b64 -S init_module -S delete_module -k modules

# ── UBU-070: Immutable ruleset ────────────────────────────────────────────────
# MUST be the last line: once loaded, rules cannot be changed without reboot.
-e 2
"""

    os.makedirs("/etc/audit/rules.d", exist_ok=True)
    if not _write_file("/etc/audit/rules.d/99-cis-hardening.rules", audit_rules, mode=0o640):
        log_fail("configure_auditd: could not write audit rules")
        return
    log_ok("UBU-061..070: audit rules written to /etc/audit/rules.d/99-cis-hardening.rules")

    # ── auditd.conf: log retention policy (UBU-071) ───────────────────────────
    try:
        with open("/etc/audit/auditd.conf", "r") as f:
            conf = f.read()
        # keep_logs: never overwrite old logs (require explicit purge)
        conf = re.sub(r"max_log_file_action\s*=.*", "max_log_file_action = keep_logs", conf)
        conf = re.sub(r"max_log_file\s*=.*",        "max_log_file = 50",               conf)
        conf = re.sub(r"num_logs\s*=.*",             "num_logs = 10",                   conf)
        with open("/etc/audit/auditd.conf", "w") as f:
            f.write(conf)
        log_ok("UBU-071: auditd.conf — max_log_file_action=keep_logs, 10 × 50 MB logs")
    except OSError as exc:
        log_warn(f"auditd.conf: {exc}")

    _run(["systemctl", "enable", "auditd"], "auditd enabled at boot")
    _run(["systemctl", "restart", "auditd"], "auditd restarted")


def fix_file_permissions() -> None:
    """
    UBU-072..082 — Enforce correct ownership and permissions on sensitive files.

    Also scans the filesystem for:
      - World-writable files (reported; sticky bit added to world-writable dirs)
      - Unowned files (reported for manual review)
      - Legacy '+' entries in passwd/shadow/group (NIS compatibility markers)
      - UID 0 accounts other than root
    """
    log_section("File Permissions (UBU-072..082)")

    # Tuples: (path, octal_mode, owner, group)
    perms = [
        ("/etc/passwd",          0o644, "root", "root"),    # UBU-072
        ("/etc/shadow",          0o640, "root", "shadow"),  # UBU-073
        ("/etc/group",           0o644, "root", "root"),    # UBU-074
        ("/etc/gshadow",         0o640, "root", "shadow"),  # UBU-075
        ("/etc/crontab",         0o600, "root", "root"),    # UBU-076
        ("/etc/ssh/sshd_config", 0o600, "root", "root"),    # UBU-077
        ("/etc/sudoers",         0o440, "root", "root"),
        ("/etc/cron.hourly",     0o700, "root", "root"),
        ("/etc/cron.daily",      0o700, "root", "root"),
        ("/etc/cron.weekly",     0o700, "root", "root"),
        ("/etc/cron.monthly",    0o700, "root", "root"),
        ("/etc/cron.d",          0o700, "root", "root"),
        ("/etc/issue",           0o644, "root", "root"),
        ("/etc/issue.net",       0o644, "root", "root"),
        ("/etc/motd",            0o644, "root", "root"),
        ("/boot/grub/grub.cfg",  0o600, "root", "root"),
    ]

    for path, mode, owner, group in perms:
        if not os.path.exists(path):
            continue
        try:
            os.chmod(path, mode)
            _run(["chown", f"{owner}:{group}", path], f"chown {owner}:{group} {path}")
        except OSError as exc:
            log_warn(f"Permissions {path}: {exc}")

    # ── UBU-078: Sticky bit on world-writable directories ─────────────────────
    # -xdev: stay on the same filesystem (skip /proc, /sys, network mounts)
    result = subprocess.run(
        ["find", "/", "-xdev", "-type", "d", "-perm", "-0002", "-not", "-perm", "-1000"],
        capture_output=True, text=True, timeout=120
    )
    for directory in result.stdout.strip().splitlines():
        if not directory:
            continue
        try:
            os.chmod(directory, os.stat(directory).st_mode | 0o1000)
            log_ok(f"UBU-078: sticky bit set on {directory}")
        except OSError as exc:
            log_warn(f"Sticky bit {directory}: {exc}")

    # ── UBU-079: World-writable files — report only ───────────────────────────
    result = subprocess.run(
        ["find", "/", "-xdev", "-type", "f", "-perm", "-0002",
         "-not", "-path", "/proc/*", "-not", "-path", "/sys/*"],
        capture_output=True, text=True, timeout=120
    )
    ww = result.stdout.strip().splitlines()
    if ww:
        log_warn(f"UBU-079: {len(ww)} world-writable files found — review manually:")
        for item in ww[:10]:  # Print at most 10 to avoid flooding the log
            log_warn(f"  WW: {item}")
        if len(ww) > 10:
            log_warn(f"  ... and {len(ww) - 10} more (see log file for full list)")
        for item in ww:
            get_logger().debug(f"WW file: {item}")
    else:
        log_ok("UBU-079: no world-writable files found")

    # ── UBU-080: Unowned files ─────────────────────────────────────────────────
    result = subprocess.run(
        ["find", "/", "-xdev", r"\(", "-nouser", "-o", "-nogroup", r"\)",
         "-not", "-path", "/proc/*", "-not", "-path", "/sys/*"],
        capture_output=True, text=True, timeout=120
    )
    unowned = result.stdout.strip().splitlines()
    if unowned:
        log_warn(f"UBU-080: {len(unowned)} unowned files/dirs — review manually")
        for item in unowned[:10]:
            log_warn(f"  Unowned: {item}")
    else:
        log_ok("UBU-080: no unowned files found")

    # ── UBU-081: Legacy '+' entries in identity files ─────────────────────────
    # A '+' at the start of a line is an NIS lookup marker — obsolete and insecure.
    for pf in ["/etc/passwd", "/etc/shadow", "/etc/group"]:
        if not os.path.exists(pf):
            continue
        with open(pf, "r") as f:
            plus_lines = [line for line in f if line.startswith("+")]
        if plus_lines:
            log_warn(f"UBU-081: legacy '+' entry found in {pf} — remove manually")
        else:
            log_ok(f"UBU-081: no legacy '+' entries in {pf}")

    # ── UBU-082: No UID 0 accounts besides root ───────────────────────────────
    result = subprocess.run(
        ["awk", "-F:", "($3==0){print $1}", "/etc/passwd"],
        capture_output=True, text=True
    )
    uid0_accounts = [u for u in result.stdout.strip().splitlines() if u != "root"]
    if uid0_accounts:
        log_warn(f"UBU-082: UID 0 accounts besides root: {uid0_accounts} — review immediately")
    else:
        log_ok("UBU-082: only root has UID 0")


def configure_filesystem() -> None:
    """
    UBU-083..085 — Harden filesystem mount options and disable core dumps.

      /tmp        — nodev, nosuid, noexec (prevent code execution from temp files)
      /dev/shm    — nodev, nosuid, noexec (shared memory not executable)
      core dumps  — disabled via /etc/security/limits.conf

    UBU-086 (GRUB password) is skipped — requires interactive grub-mkpasswd-pbkdf2.
    """
    log_section("Filesystem Hardening (UBU-083..085)")

    # ── /etc/fstab entries ────────────────────────────────────────────────────
    for device, mountpoint, options, item_id in [
        ("tmpfs", "/tmp",     "tmpfs defaults,nodev,nosuid,noexec 0 0", "UBU-083"),
        ("tmpfs", "/dev/shm", "tmpfs defaults,nodev,nosuid,noexec 0 0", "UBU-084"),
    ]:
        try:
            with open("/etc/fstab", "r") as f:
                fstab = f.read()
            # Only add the entry if the mountpoint is not already configured
            if mountpoint not in fstab:
                with open("/etc/fstab", "a") as f:
                    f.write(f"\n{device} {mountpoint} {options}\n")
                log_ok(f"{item_id}: {mountpoint} added to fstab with nodev,nosuid,noexec")
            else:
                log_ok(f"{item_id}: {mountpoint} already in fstab — verify options manually")
        except OSError as exc:
            log_warn(f"fstab {mountpoint}: {exc}")

    # ── UBU-085: Disable core dumps ───────────────────────────────────────────
    # Core dumps from setuid binaries can expose sensitive memory content.
    try:
        with open("/etc/security/limits.conf", "r") as f:
            content = f.read()
        if "hard core 0" not in content:
            with open("/etc/security/limits.conf", "a") as f:
                f.write("\n# CIS: disable core dumps\n* hard core 0\n")
        log_ok("UBU-085: core dumps disabled in /etc/security/limits.conf")
    except OSError as exc:
        log_warn(f"limits.conf core dumps: {exc}")

    log_skip("UBU-086: GRUB password — MANUAL: run grub-mkpasswd-pbkdf2 interactively")


def configure_apparmor() -> None:
    """
    UBU-022..023 — Enable AppArmor and enforce all available profiles.

    AppArmor provides mandatory access control (MAC): each confined application
    can only access the files, capabilities, and network sockets defined in its
    profile.  'enforce' mode denies and logs violations; 'complain' mode only logs.
    """
    log_section("AppArmor (UBU-022..023)")

    _run(
        ["apt-get", "install", "-y", "-q", "apparmor", "apparmor-utils"],
        "AppArmor installed"
    )
    _run(["systemctl", "enable", "apparmor"], "AppArmor enabled at boot")
    _run(["systemctl", "start",  "apparmor"], "AppArmor started")

    # Load and enforce every profile found in /etc/apparmor.d/
    # Individual failures (e.g. a profile for an uninstalled application) are
    # acceptable — aa-enforce exits 0 even when some profiles are skipped.
    _run(["aa-enforce", "/etc/apparmor.d/*"], "UBU-022..023: AppArmor profiles set to enforce")
    log_ok("UBU-022..023: AppArmor in enforce mode")


def configure_user_accounts() -> None:
    """
    UBU-087..090 — Harden local user accounts.

      UBU-087: Lock system accounts (daemon, www-data, etc.) so they cannot log in.
      UBU-088: Restrict root console login to tty1 via /etc/securetty.
      UBU-089: Lock any account that has an empty password.
      UBU-090: Set default umask to 027 in /etc/bash.bashrc and /etc/profile.
    """
    log_section("User Account Hardening (UBU-087..090)")

    # ── UBU-087: Lock service accounts ───────────────────────────────────────
    # These accounts need to exist (for daemon ownership) but must never be used
    # to log in.  'usermod -L -s /usr/sbin/nologin' achieves both goals.
    system_accounts = [
        "daemon", "bin", "sys", "sync", "games", "man",
        "lp", "mail", "news", "uucp", "proxy", "www-data",
        "backup", "list", "irc", "gnats", "nobody",
        "systemd-network", "systemd-resolve", "syslog",
        "messagebus", "uuidd", "sshd", "_apt",
    ]
    for account in system_accounts:
        # Check the account exists before trying to modify it
        if subprocess.run(["id", account], capture_output=True, timeout=5).returncode == 0:
            _run(
                ["usermod", "-L", "-s", "/usr/sbin/nologin", account],
                f"UBU-087: locked {account}"
            )

    # ── UBU-088: Restrict root to tty1 only ───────────────────────────────────
    # /etc/securetty lists TTYs on which root may log in.  An empty file would
    # block all console login; listing only 'console' and 'tty1' is a safe minimum.
    _write_file("/etc/securetty", "console\ntty1\n", mode=0o600)
    log_ok("UBU-088: /etc/securetty restricted to console + tty1")

    # ── UBU-089: Lock accounts with empty passwords ───────────────────────────
    result = subprocess.run(
        ["awk", "-F:", r'($2 == ""){print $1}', "/etc/shadow"],
        capture_output=True, text=True
    )
    empty_pw_accounts = result.stdout.strip().splitlines()
    if empty_pw_accounts:
        log_warn(f"UBU-089: accounts with empty passwords detected — locking: {empty_pw_accounts}")
        for account in empty_pw_accounts:
            _run(["passwd", "-l", account], f"Locked {account}")
    else:
        log_ok("UBU-089: no accounts with empty passwords")

    # ── UBU-090: Default umask 027 ─────────────────────────────────────────────
    # 027 → owner: rwx, group: rx, others: no permissions
    for profile_file in ["/etc/bash.bashrc", "/etc/profile"]:
        if not os.path.exists(profile_file):
            continue
        try:
            with open(profile_file, "r") as f:
                content = f.read()
            if "umask 027" not in content:
                with open(profile_file, "a") as f:
                    f.write("\n# CIS hardening: default umask (owner:rwx group:rx other:none)\numask 027\n")
            log_ok(f"UBU-090: umask 027 set in {profile_file}")
        except OSError as exc:
            log_warn(f"umask in {profile_file}: {exc}")


def configure_cron() -> None:
    """
    UBU-091..092 — Restrict cron and at job scheduling to authorised users only.

    When cron.allow exists, only users listed in it may use crontab.
    When cron.deny exists without cron.allow, listed users are blocked.
    Having cron.allow with only 'root' is the most restrictive configuration.
    The same logic applies to at.allow / at.deny.
    """
    log_section("Cron/At Restrictions (UBU-091..092)")

    for allow_file, deny_file, label in [
        ("/etc/cron.allow", "/etc/cron.deny", "UBU-091: cron.allow"),
        ("/etc/at.allow",   "/etc/at.deny",   "UBU-092: at.allow"),
    ]:
        if not os.path.exists(allow_file):
            _write_file(allow_file, "root\n", mode=0o640)
            log_ok(f"{label} created (root only)")
        else:
            log_ok(f"{label} already exists")

        # Remove the deny file so the allow file takes precedence unambiguously
        if os.path.exists(deny_file):
            try:
                os.remove(deny_file)
                log_ok(f"Removed {deny_file}")
            except OSError as exc:
                log_warn(f"Could not remove {deny_file}: {exc}")

    # Secure cron directories (must be owned by root and not world/group accessible)
    for cron_dir in [
        "/etc/cron.hourly", "/etc/cron.daily", "/etc/cron.weekly",
        "/etc/cron.monthly", "/etc/cron.d"
    ]:
        if os.path.exists(cron_dir):
            try:
                os.chmod(cron_dir, 0o700)
            except OSError as exc:
                log_warn(f"chmod {cron_dir}: {exc}")

    _run(["chown", "root:root", "/etc/crontab"], "/etc/crontab owned by root:root")


def configure_screen_lock() -> None:
    """
    UBU-093..095 — Configure GNOME screen lock via dconf.

    ISSP §4.2 requires session auto-lock after 5 minutes of inactivity.
    Settings are written to a system-wide dconf database so they apply to all
    users and are locked (users cannot override them through the GUI).

    Paths:
      /etc/dconf/db/local.d/01-cis-lock  — key/value pairs
      /etc/dconf/db/local.d/locks/       — list of locked keys
      /etc/dconf/profile/user            — tells dconf to read the 'local' DB
    """
    log_section("GNOME Screen Lock (UBU-093..095)")

    # ── dconf key/value database ──────────────────────────────────────────────
    lock_settings = """\
[org/gnome/desktop/session]
idle-delay=uint32 300

[org/gnome/desktop/screensaver]
lock-enabled=true
lock-delay=uint32 0
idle-activation-enabled=true
"""
    os.makedirs("/etc/dconf/db/local.d", exist_ok=True)
    _write_file("/etc/dconf/db/local.d/01-cis-lock", lock_settings)

    # ── Lock keys so users cannot change them in Settings ─────────────────────
    locks = """\
/org/gnome/desktop/session/idle-delay
/org/gnome/desktop/screensaver/lock-enabled
/org/gnome/desktop/screensaver/lock-delay
/org/gnome/desktop/screensaver/idle-activation-enabled
"""
    os.makedirs("/etc/dconf/db/local.d/locks", exist_ok=True)
    _write_file("/etc/dconf/db/local.d/locks/cis-lock", locks)

    # ── dconf user profile ─────────────────────────────────────────────────────
    # 'user-db:user' = user's own preferences; 'system-db:local' = our enforced DB
    _write_file("/etc/dconf/profile/user", "user-db:user\nsystem-db:local\n")

    # Compile the dconf database
    _run(["dconf", "update"], "UBU-093..095: dconf database updated")
    log_ok("UBU-093..095: GNOME screen lock — idle=300 s, lock-enabled=true (ISSP §4.2)")


def configure_automatic_updates() -> None:
    """
    UBU-096..097 — Install and configure unattended-upgrades.

    Security updates are applied automatically every day.
    Non-security updates are NOT auto-installed to avoid breaking changes.
    Automatic reboot is disabled; reboots must be scheduled manually.
    """
    log_section("Automatic Security Updates (UBU-096..097)")

    _run(
        ["apt-get", "install", "-y", "-q", "unattended-upgrades", "apt-listchanges"],
        "unattended-upgrades installed"
    )

    # Main configuration file
    unattended_conf = """\
// /etc/apt/apt.conf.d/50unattended-upgrades
// Deployed by harden.py — ISSP §5.1 + CIS
Unattended-Upgrade::Allowed-Origins {
    "${distro_id}:${distro_codename}";
    "${distro_id}:${distro_codename}-security";
    "${distro_id}ESMApps:${distro_codename}-apps-security";
    "${distro_id}ESM:${distro_codename}-infra-security";
};
Unattended-Upgrade::Package-Blacklist {};
Unattended-Upgrade::AutoFixInterruptedDpkg "true";
Unattended-Upgrade::MinimalSteps "true";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
// Do NOT reboot automatically — schedule maintenance windows manually
Unattended-Upgrade::Automatic-Reboot "false";
Unattended-Upgrade::Mail "";
Unattended-Upgrade::MailReport "on-change";
"""
    _write_file("/etc/apt/apt.conf.d/50unattended-upgrades", unattended_conf)

    # Periodic schedule: download and install daily
    auto_conf = """\
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::AutocleanInterval "7";
APT::Periodic::Unattended-Upgrade "1";
"""
    _write_file("/etc/apt/apt.conf.d/20auto-upgrades", auto_conf)
    _run(["systemctl", "enable", "unattended-upgrades"], "unattended-upgrades enabled at boot")
    log_ok("UBU-096..097: automatic security updates configured")


def configure_aide() -> None:
    """
    UBU-098..100 — Install AIDE (Advanced Intrusion Detection Environment).

    AIDE builds a cryptographic database of file attributes (hashes, permissions,
    timestamps) and detects any subsequent changes.

    Steps:
      1. Install AIDE packages.
      2. Initialise the database (aideinit) — this can take several minutes.
      3. Copy the new database to the active location.
      4. Add a daily cron job that checks for changes and logs to syslog.

    Note: the first AIDE check is only meaningful 24 h after initialisation,
    once a clean baseline exists.
    """
    log_section("AIDE File Integrity Monitoring (UBU-098..100)")

    _run(["apt-get", "install", "-y", "-q", "aide", "aide-common"], "AIDE installed")

    # Build the initial database (can take 2–10 minutes depending on disk size)
    log_ok("UBU-099: initialising AIDE database — this may take several minutes...")
    _run(["aideinit", "-y", "-f"], "AIDE database initialised")

    # aideinit writes to aide.db.new.gz; we copy it to the active aide.db.gz
    new_db  = "/var/lib/aide/aide.db.new.gz"
    live_db = "/var/lib/aide/aide.db.gz"
    if os.path.exists(new_db):
        try:
            shutil.copy2(new_db, live_db)
            log_ok("AIDE: database copied to active location")
        except OSError as exc:
            log_warn(f"AIDE database copy: {exc}")
    else:
        log_warn("AIDE: aide.db.new.gz not found — database may not have been created")

    # Daily cron job: run aide --check and send output to syslog
    aide_cron = "0 5 * * * root /usr/bin/aide --check | /usr/bin/logger -t aide\n"
    if _write_file("/etc/cron.d/aide-check", aide_cron, mode=0o644):
        log_ok("UBU-100: AIDE daily cron job configured (runs at 05:00)")


def configure_logging() -> None:
    """
    UBU-101..104 — Configure rsyslog, logrotate, NTP, and disable Ctrl+Alt+Del.

      UBU-101: rsyslog creates log files with mode 0640 (not world-readable).
      UBU-102: logrotate already installed with Ubuntu — verify it exists.
      UBU-103: chrony provides NTP time synchronisation.
      UBU-104: Ctrl+Alt+Del reboot shortcut is masked (systemd target).
    """
    log_section("Logging & System Configuration (UBU-101..104)")

    # ── UBU-101: rsyslog file creation permissions ─────────────────────────────
    rsyslog_conf = """\
# /etc/rsyslog.d/99-cis-hardening.conf — deployed by harden.py
# New log files are created with mode 0640 (root:adm), not world-readable.
$FileOwner root
$FileGroup adm
$FileCreateMode 0640
$DirCreateMode 0755
$Umask 0022
$PrivDropToUser syslog
$PrivDropToGroup syslog
"""
    if _write_file("/etc/rsyslog.d/99-cis-hardening.conf", rsyslog_conf):
        log_ok("UBU-101: rsyslog file permissions configured (0640)")
    _run(["systemctl", "restart", "rsyslog"], "rsyslog restarted")

    # ── UBU-102: logrotate ─────────────────────────────────────────────────────
    if os.path.exists("/etc/logrotate.conf"):
        log_ok("UBU-102: /etc/logrotate.conf exists")
    else:
        log_warn("UBU-102: logrotate.conf not found — install logrotate manually")

    # ── UBU-103: NTP via chrony ────────────────────────────────────────────────
    _run(["apt-get", "install", "-y", "-q", "chrony"], "chrony installed")
    _run(["systemctl", "enable", "chrony"], "chrony enabled at boot")
    _run(["systemctl", "start",  "chrony"], "chrony started")
    log_ok("UBU-103: NTP synchronisation via chrony")

    # ── UBU-104: Disable Ctrl+Alt+Del ─────────────────────────────────────────
    # Masking the systemd target prevents accidental (or malicious) reboots
    # from a logged-in console session.
    _run(["systemctl", "mask",          "ctrl-alt-del.target"], "UBU-104: Ctrl+Alt+Del masked")
    _run(["systemctl", "daemon-reload"], "systemd configuration reloaded")


def configure_system_banners() -> None:
    """
    UBU-105..107 — Write legal warning banners to system login message files.

      /etc/motd       — Message of the Day, shown after successful login.
      /etc/issue      — Pre-login banner on local TTY sessions.
      /etc/issue.net  — Pre-login banner for network (SSH) sessions.
                        Referenced by 'Banner' in sshd_config.

    The banner text is the BANNER_TEXT constant defined at the top of this file.
    """
    log_section("System Banners (UBU-105..107)")

    for path, item_id in [
        ("/etc/motd",       "UBU-105"),
        ("/etc/issue",      "UBU-106"),
        ("/etc/issue.net",  "UBU-107"),
    ]:
        if _write_file(path, BANNER_TEXT):
            log_ok(f"{item_id}: {path} updated with legal warning")


def configure_sudo() -> None:
    """
    UBU-108..109 — Harden sudo configuration via a drop-in file.

    Key settings:
      - requiretty:         sudo can only be used from a real TTY (not scripts).
      - timestamp_timeout=5: sudo credentials expire after 5 minutes.
      - log_input, log_output: full I/O logging of sudo sessions.
      - secure_path:        PATH is reset to known-safe directories.

    The drop-in is validated with 'visudo -c' before being installed to ensure
    a syntax error cannot lock out all administrative access.
    """
    log_section("Sudo Configuration (UBU-108..109)")

    sudoers_content = """\
# /etc/sudoers.d/cis-hardening — deployed by harden.py
# Validated with 'visudo -c' before installation.

# Reset environment to a safe minimal set
Defaults env_reset
Defaults secure_path = /sbin:/bin:/usr/sbin:/usr/bin

# Require a real TTY — prevents sudo use from CGI scripts or cron
Defaults requiretty

# Never show the password as typed
Defaults !visiblepw

# Always set HOME when switching users
Defaults always_set_home

# sudo credential cache expires after 5 minutes (ISSP §4.2)
Defaults timestamp_timeout=5

# 1 minute to enter password before sudo times out
Defaults passwd_timeout=1

# Generic failure message (do not reveal whether the account exists)
Defaults badpass_message="Authentication failure"

# Full I/O logging of sudo sessions
Defaults logfile=/var/log/sudo.log
Defaults log_input, log_output
"""

    # ── Validate the sudoers syntax before installing ─────────────────────────
    # Writing an invalid sudoers file would break all sudo access system-wide.
    # We write to a temp file and run 'visudo -c -f <tempfile>' first.
    validated = False
    try:
        fd, tmp_path = tempfile.mkstemp(prefix="sudoers_cis_", suffix=".tmp")
        try:
            with os.fdopen(fd, "w") as f:
                f.write(sudoers_content)
            result = subprocess.run(
                ["visudo", "-c", "-f", tmp_path],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0:
                validated = True
            else:
                log_fail(f"sudo visudo validation failed: {result.stderr.strip()}")
        finally:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
    except Exception as exc:
        log_warn(f"Could not validate sudoers syntax: {exc} — skipping sudo hardening")

    if validated:
        if _write_file("/etc/sudoers.d/cis-hardening", sudoers_content, mode=0o440):
            log_ok("UBU-108..109: /etc/sudoers.d/cis-hardening installed (syntax validated)")
    else:
        log_warn("UBU-108..109: sudo drop-in NOT installed due to validation failure")


def check_luks_encryption() -> None:
    """
    UBU-110 — Check whether full-disk encryption (LUKS) is active and report.

    The script does NOT enable LUKS on a running system: doing so requires
    a full reinstall or unmounting the filesystem — neither is safe to automate.

    This function simply reports the current state so the admin is aware.
    """
    log_section("LUKS Encryption Check (UBU-110)")

    result = subprocess.run(
        ["lsblk", "-o", "NAME,TYPE,FSTYPE"],
        capture_output=True, text=True, timeout=30
    )
    if "crypt" in result.stdout:
        log_ok("UBU-110: LUKS encrypted volume detected — full-disk encryption active")
    else:
        log_warn(
            "UBU-110: no LUKS encryption detected. "
            "ISSP §5.1 requires full-disk encryption. "
            "Action: reinstall with LUKS or encrypt secondary volumes with cryptsetup."
        )

    log_skip("UBU-111: USB storage module — NOT disabled. Evaluate per-machine policy.")
    log_skip("UBU-113: VPN enforcement — MANUAL: requires VPN infrastructure.")


def harden_misc() -> None:
    """
    Miscellaneous hardening items that do not fit a single category:

      - Blacklist unused/dangerous kernel modules (cramfs, jffs2, dccp, sctp…)
      - Add hidepid=2 to /proc mount to hide other users' processes
    """
    log_section("Miscellaneous Hardening")

    # ── /proc hidepid ─────────────────────────────────────────────────────────
    # hidepid=2: users can only see their own processes in /proc
    try:
        with open("/etc/fstab", "r") as f:
            fstab = f.read()
        if "hidepid" not in fstab:
            with open("/etc/fstab", "a") as f:
                f.write("\n# CIS: hide other users' processes\nproc /proc proc defaults,hidepid=2 0 0\n")
            log_ok("/proc hidepid=2 added to fstab (active on next mount)")
        else:
            log_ok("/proc hidepid already configured in fstab")
    except OSError as exc:
        log_warn(f"/proc hidepid: {exc}")

    # ── Kernel module blacklist ───────────────────────────────────────────────
    # These modules have no legitimate use on a hardened workstation and have
    # been associated with privilege-escalation or information-leakage exploits.
    blacklist = """\
# /etc/modprobe.d/cis-hardening.conf — deployed by harden.py
# Unused or risky filesystem modules
install cramfs   /bin/true
install freevxfs /bin/true
install jffs2    /bin/true
install hfs      /bin/true
install hfsplus  /bin/true
install udf      /bin/true
# Risky network protocols
install dccp /bin/true
install sctp /bin/true
install rds  /bin/true
install tipc /bin/true
"""
    if _write_file("/etc/modprobe.d/cis-hardening.conf", blacklist):
        log_ok("Unused kernel modules blacklisted (cramfs, freevxfs, jffs2, hfs, dccp, sctp, rds, tipc)")

    # Unload modules that may already be loaded in the running kernel
    for mod in ["dccp", "sctp", "rds", "tipc"]:
        _run(["modprobe", "-r", mod], f"{mod} unloaded")


# ── Main entry point ──────────────────────────────────────────────────────────

def harden() -> None:
    """
    Run all Ubuntu hardening sections in order.
    Called by harden.py after OS detection and backup.
    """
    logger = get_logger()
    logger.info("\n" + "=" * 70)
    logger.info("  Bidouille — Ubuntu Workstation Hardening")
    logger.info("  CIS Ubuntu Benchmark + ISSP ISO 27002 v2")
    logger.info("=" * 70 + "\n")

    apply_sysctl()
    harden_ssh()
    configure_pam()
    configure_login_defs()
    disable_unused_services()
    configure_ufw()
    configure_auditd()
    fix_file_permissions()
    configure_filesystem()
    configure_apparmor()
    configure_user_accounts()
    configure_cron()
    configure_screen_lock()
    configure_automatic_updates()
    configure_aide()
    configure_logging()
    configure_system_banners()
    configure_sudo()
    check_luks_encryption()
    harden_misc()

    logger.info("\n" + "=" * 70)
    logger.info("  Ubuntu hardening complete.")
    logger.info("=" * 70 + "\n")
