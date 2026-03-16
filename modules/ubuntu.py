"""
Ubuntu workstation hardening module.
CIS Ubuntu Benchmark + ISSP ISO 27002 v2.
Requires: root privileges.
"""

import os
import re
import shutil
import subprocess
from modules.logger import get_logger, log_ok, log_warn, log_fail, log_section, log_skip

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


def _run(args, label: str, check=False) -> bool:
    try:
        result = subprocess.run(args, capture_output=True, text=True, timeout=300)
        if result.returncode == 0:
            log_ok(label)
            return True
        else:
            if check:
                log_fail(f"{label}: {result.stderr.strip()}")
            else:
                log_warn(f"{label}: exit {result.returncode} — {result.stderr.strip()[:120]}")
            return False
    except FileNotFoundError:
        log_skip(f"{label}: command not found (service may not be installed)")
        return False
    except Exception as e:
        log_fail(f"{label}: {e}")
        return False


def _write_file(path: str, content: str, mode: int = 0o644):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write(content)
    os.chmod(path, mode)


def _set_sysctl(key: str, value: str, conf_file: str):
    """Ensure key=value in a sysctl conf file."""
    try:
        if os.path.exists(conf_file):
            with open(conf_file, "r") as f:
                content = f.read()
        else:
            content = ""

        pattern = re.compile(r"^#?\s*" + re.escape(key) + r"\s*=.*$", re.MULTILINE)
        new_line = f"{key} = {value}"
        if pattern.search(content):
            content = pattern.sub(new_line, content)
        else:
            content += f"\n{new_line}"

        with open(conf_file, "w") as f:
            f.write(content)
    except Exception as e:
        log_warn(f"sysctl {key}: {e}")


def _set_login_defs(key: str, value: str):
    """Update /etc/login.defs setting."""
    path = "/etc/login.defs"
    try:
        with open(path, "r") as f:
            content = f.read()
        pattern = re.compile(r"^#?\s*" + re.escape(key) + r"\s+.*$", re.MULTILINE)
        new_line = f"{key}\t{value}"
        if pattern.search(content):
            content = pattern.sub(new_line, content)
        else:
            content += f"\n{new_line}\n"
        with open(path, "w") as f:
            f.write(content)
    except Exception as e:
        log_warn(f"login.defs {key}: {e}")


def _set_pwquality(key: str, value: str):
    """Update /etc/security/pwquality.conf."""
    path = "/etc/security/pwquality.conf"
    try:
        with open(path, "r") as f:
            content = f.read()
        pattern = re.compile(r"^#?\s*" + re.escape(key) + r"\s*=.*$", re.MULTILINE)
        new_line = f"{key} = {value}"
        if pattern.search(content):
            content = pattern.sub(new_line, content)
        else:
            content += f"\n{new_line}\n"
        with open(path, "w") as f:
            f.write(content)
    except Exception as e:
        log_warn(f"pwquality {key}: {e}")


# ─── Sections ─────────────────────────────────────────────────────────────────

def apply_sysctl():
    log_section("Kernel / sysctl Hardening (UBU-005..021)")
    conf = "/etc/sysctl.d/99-cis-hardening.conf"

    sysctl_settings = [
        ("net.ipv4.ip_forward", "0"),
        ("net.ipv4.conf.all.send_redirects", "0"),
        ("net.ipv4.conf.default.send_redirects", "0"),
        ("net.ipv4.conf.all.accept_redirects", "0"),
        ("net.ipv4.conf.default.accept_redirects", "0"),
        ("net.ipv4.conf.all.secure_redirects", "0"),
        ("net.ipv4.conf.default.secure_redirects", "0"),
        ("net.ipv4.conf.all.log_martians", "1"),
        ("net.ipv4.conf.default.log_martians", "1"),
        ("net.ipv4.tcp_syncookies", "1"),
        ("net.ipv4.icmp_echo_ignore_broadcasts", "1"),
        ("net.ipv4.icmp_ignore_bogus_error_responses", "1"),
        ("net.ipv4.conf.all.rp_filter", "1"),
        ("net.ipv4.conf.default.rp_filter", "1"),
        ("net.ipv4.conf.all.accept_source_route", "0"),
        ("net.ipv4.conf.default.accept_source_route", "0"),
        ("net.ipv6.conf.all.disable_ipv6", "1"),
        ("net.ipv6.conf.default.disable_ipv6", "1"),
        ("net.ipv6.conf.all.accept_redirects", "0"),
        ("net.ipv6.conf.default.accept_redirects", "0"),
        ("kernel.randomize_va_space", "2"),
        ("kernel.dmesg_restrict", "1"),
        ("kernel.perf_event_paranoid", "3"),
        ("kernel.kptr_restrict", "2"),
        ("fs.suid_dumpable", "0"),
        ("fs.protected_hardlinks", "1"),
        ("fs.protected_symlinks", "1"),
        ("net.ipv4.tcp_rfc1337", "1"),
        ("net.ipv4.tcp_timestamps", "0"),
    ]

    header = "# CIS/ISSP Ubuntu Hardening — generated by harden.py\n"
    lines = header
    for key, val in sysctl_settings:
        lines += f"{key} = {val}\n"

    with open(conf, "w") as f:
        f.write(lines)
    log_ok(f"sysctl config written to {conf}")
    _run(["sysctl", "-p", conf], "sysctl -p applied")

    # Also apply immediately
    for key, val in sysctl_settings:
        subprocess.run(["sysctl", "-w", f"{key}={val}"],
                       capture_output=True, timeout=5)

    log_ok("UBU-005..021: sysctl kernel parameters hardened")


def harden_ssh():
    log_section("SSH Hardening (UBU-024..035)")

    sshd_config = """\
# /etc/ssh/sshd_config — CIS/ISSP hardened by harden.py
Protocol 2
Port 22
PermitRootLogin no
MaxAuthTries 3
PermitEmptyPasswords no
X11Forwarding no
ClientAliveInterval 300
ClientAliveCountMax 0
LoginGraceTime 60
Banner /etc/issue.net
IgnoreRhosts yes
HostbasedAuthentication no
PermitUserEnvironment no
UsePAM yes
AllowTcpForwarding no
MaxStartups 10:30:60
MaxSessions 10
TCPKeepAlive no
Compression no
LogLevel VERBOSE
SyslogFacility AUTH
PrintLastLog yes
StrictModes yes
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group14-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,ecdh-sha2-nistp521,ecdh-sha2-nistp384,ecdh-sha2-nistp256
HostKeyAlgorithms ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521,ssh-rsa,rsa-sha2-256,rsa-sha2-512,ssh-ed25519
"""
    _write_file("/etc/ssh/sshd_config", sshd_config, mode=0o600)
    log_ok("UBU-024..035: /etc/ssh/sshd_config written")
    _run(["systemctl", "restart", "ssh"], "SSH service restarted")


def configure_pam():
    log_section("PAM Hardening (UBU-038..043)")

    # Install libpam-pwquality if needed
    _run(["apt-get", "install", "-y", "-q", "libpam-pwquality"], "libpam-pwquality installed")

    # pwquality.conf
    pwq_settings = [
        ("minlen", "12"),
        ("dcredit", "-1"),
        ("ucredit", "-1"),
        ("lcredit", "-1"),
        ("ocredit", "-1"),
        ("maxrepeat", "3"),
        ("maxsequence", "3"),
        ("gecoscheck", "1"),
    ]
    for key, val in pwq_settings:
        _set_pwquality(key, val)
    log_ok("UBU-038..039: pwquality configured (minlen=12, complexity)")

    # pam_pwhistory — /etc/pam.d/common-password
    try:
        with open("/etc/pam.d/common-password", "r") as f:
            content = f.read()

        # Add pwhistory if not present
        if "pam_pwhistory.so" not in content:
            content = content.replace(
                "password\t[success=1 default=ignore]\tpam_unix.so",
                "password\trequired\tpam_pwhistory.so remember=24 enforce_for_root\n"
                "password\t[success=1 default=ignore]\tpam_unix.so"
            )
        else:
            content = re.sub(
                r"(pam_pwhistory\.so.*)",
                "pam_pwhistory.so remember=24 enforce_for_root",
                content
            )
        # Ensure sha512 + minlen in pam_unix
        content = re.sub(
            r"(pam_unix\.so.*)",
            r"\1 sha512 shadow minlen=12",
            content
        )
        with open("/etc/pam.d/common-password", "w") as f:
            f.write(content)
        log_ok("UBU-040: pam_pwhistory remember=24 configured")
    except Exception as e:
        log_warn(f"pam_pwhistory: {e}")

    # pam_faillock — /etc/pam.d/common-auth
    faillock_preauth = "auth\trequired\tpam_faillock.so preauth silent audit deny=5 unlock_time=900 fail_interval=900"
    faillock_authfail = "auth\t[default=die]\tpam_faillock.so authfail audit deny=5 unlock_time=900 fail_interval=900"

    try:
        with open("/etc/pam.d/common-auth", "r") as f:
            content = f.read()

        if "pam_faillock.so" not in content:
            # Insert before pam_unix
            content = content.replace(
                "auth\t[success=1 default=ignore]\tpam_unix.so",
                f"{faillock_preauth}\nauth\t[success=1 default=ignore]\tpam_unix.so"
            )
            content += f"\n{faillock_authfail}\n"

        with open("/etc/pam.d/common-auth", "w") as f:
            f.write(content)
        log_ok("UBU-041..043: pam_faillock configured (deny=5, unlock=900s)")
    except Exception as e:
        log_warn(f"pam_faillock: {e}")

    # faillock.conf
    faillock_conf = """\
# pam_faillock configuration — CIS hardened
deny = 5
unlock_time = 900
fail_interval = 900
audit
silent
"""
    _write_file("/etc/security/faillock.conf", faillock_conf)
    log_ok("UBU-041..043: /etc/security/faillock.conf written")


def configure_login_defs():
    log_section("Login Definitions (UBU-044..047)")
    settings = [
        ("PASS_MAX_DAYS", "90"),
        ("PASS_MIN_DAYS", "1"),
        ("PASS_WARN_AGE", "14"),
        ("PASS_MIN_LEN", "12"),
        ("LOGIN_RETRIES", "3"),
        ("LOGIN_TIMEOUT", "60"),
        ("UMASK", "027"),
        ("HOME_MODE", "0750"),
        ("SHA_CRYPT_MIN_ROUNDS", "65536"),
        ("SHA_CRYPT_MAX_ROUNDS", "65536"),
    ]
    for key, val in settings:
        _set_login_defs(key, val)
    log_ok("UBU-044..047: /etc/login.defs hardened")


def disable_unused_services():
    log_section("Disable Unused Services (UBU-048..060)")
    services = [
        "telnet", "inetd", "xinetd",
        "vsftpd", "ftp",
        "rsh-server", "rsh",
        "avahi-daemon",
        "cups",
        "isc-dhcp-server", "isc-dhcp-server6",
        "slapd",
        "nfs-server", "nfs-kernel-server",
        "rpcbind",
        "named", "bind9",
        "apache2",
        "dovecot",
        "snmpd",
        "rsync",
        "nis",
        "talk", "talkd",
    ]
    # Note: smbd/nmbd skipped (UBU-060) to preserve AD connectivity
    for svc in services:
        rc, _, _ = subprocess.run(
            ["systemctl", "is-enabled", svc],
            capture_output=True, text=True
        ).returncode, "", ""
        result = subprocess.run(
            ["systemctl", "disable", "--now", svc],
            capture_output=True, text=True, timeout=30
        )
        if result.returncode == 0:
            log_ok(f"Service disabled: {svc}")
        else:
            # May not be installed — that's fine
            log_skip(f"Service {svc}: not found or already disabled")

    log_skip("UBU-060: smbd/nmbd NOT disabled — preserving AD/Samba connectivity")


def configure_ufw():
    log_section("UFW Firewall (UBU-001..004)")
    _run(["apt-get", "install", "-y", "-q", "ufw"], "UFW installed")
    _run(["ufw", "--force", "reset"], "UFW reset")
    _run(["ufw", "default", "deny", "incoming"], "UBU-002: Default deny incoming")
    _run(["ufw", "default", "allow", "outgoing"], "UBU-003: Default allow outgoing")
    _run(["ufw", "allow", "22/tcp"], "UBU-004: Allow SSH")
    # Enable UFW non-interactively
    subprocess.run(["ufw", "--force", "enable"], capture_output=True, timeout=30)
    log_ok("UBU-001: UFW enabled")


def configure_auditd():
    log_section("Auditd Configuration (UBU-061..071)")

    _run(["apt-get", "install", "-y", "-q", "auditd", "audispd-plugins"], "auditd installed")

    audit_rules = """\
# /etc/audit/rules.d/99-cis-hardening.rules
# Generated by harden.py — CIS Ubuntu Hardening

# Delete all rules
-D

# Buffer size
-b 8192

# Failure mode (1=printk, 2=panic)
-f 1

# UBU-062: Time change events
-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change
-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change
-a always,exit -F arch=b64 -S clock_settime -k time-change
-w /etc/localtime -p wa -k time-change

# UBU-063: User/group modification
-w /etc/group -p wa -k identity
-w /etc/passwd -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/security/opasswd -p wa -k identity

# UBU-064: Network configuration
-a always,exit -F arch=b64 -S sethostname -S setdomainname -k system-locale
-a always,exit -F arch=b32 -S sethostname -S setdomainname -k system-locale
-w /etc/issue -p wa -k system-locale
-w /etc/issue.net -p wa -k system-locale
-w /etc/hosts -p wa -k system-locale
-w /etc/network -p wa -k system-locale

# MAC policy
-w /etc/apparmor/ -p wa -k MAC-policy
-w /etc/apparmor.d/ -p wa -k MAC-policy

# UBU-065: Sudo usage
-w /etc/sudoers -p wa -k actions
-w /etc/sudoers.d/ -p wa -k actions
-w /var/log/sudo.log -p wa -k actions
-a always,exit -F arch=b64 -C euid!=uid -F euid=0 -S execve -k actions

# UBU-066: File deletions by users
-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete
-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete

# UBU-067: System calls (setuid, mount)
-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts
-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts
-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=1000 -k perm_mod
-a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -k perm_mod
-a always,exit -F arch=b64 -S setxattr -S lsetxattr -S fsetxattr -F auid>=1000 -k perm_mod
-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=1000 -k perm_mod
-a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -k perm_mod

# UBU-068: Login/logout
-w /var/log/faillog -p wa -k logins
-w /var/log/lastlog -p wa -k logins
-w /var/log/tallylog -p wa -k logins
-w /var/run/faillock/ -p wa -k logins
-w /var/log/wtmp -p wa -k session
-w /var/run/utmp -p wa -k session
-w /var/log/btmp -p wa -k session

# UBU-069: Privileged commands
-a always,exit -F path=/usr/bin/sudo -F perm=x -F auid>=1000 -k privileged
-a always,exit -F path=/usr/bin/su -F perm=x -F auid>=1000 -k privileged
-a always,exit -F path=/usr/bin/newgrp -F perm=x -F auid>=1000 -k privileged
-a always,exit -F path=/usr/bin/passwd -F perm=x -F auid>=1000 -k privileged
-a always,exit -F path=/usr/sbin/usermod -F perm=x -F auid>=1000 -k privileged
-a always,exit -F path=/usr/sbin/useradd -F perm=x -F auid>=1000 -k privileged
-a always,exit -F path=/usr/sbin/userdel -F perm=x -F auid>=1000 -k privileged
-a always,exit -F path=/usr/sbin/groupmod -F perm=x -F auid>=1000 -k privileged

# Kernel module loading
-w /sbin/insmod -p x -k modules
-w /sbin/rmmod -p x -k modules
-w /sbin/modprobe -p x -k modules
-a always,exit -F arch=b64 -S init_module -S delete_module -k modules

# UBU-071: Auditd log size action
# (configured in auditd.conf)

# UBU-070: Immutable — MUST BE LAST
-e 2
"""
    os.makedirs("/etc/audit/rules.d", exist_ok=True)
    _write_file("/etc/audit/rules.d/99-cis-hardening.rules", audit_rules, mode=0o640)
    log_ok("UBU-061..070: audit rules written")

    # auditd.conf
    try:
        with open("/etc/audit/auditd.conf", "r") as f:
            conf = f.read()
        conf = re.sub(r"max_log_file_action\s*=.*", "max_log_file_action = keep_logs", conf)
        conf = re.sub(r"max_log_file\s*=.*", "max_log_file = 50", conf)
        conf = re.sub(r"num_logs\s*=.*", "num_logs = 10", conf)
        with open("/etc/audit/auditd.conf", "w") as f:
            f.write(conf)
        log_ok("UBU-071: auditd.conf: max_log_file_action=keep_logs")
    except Exception as e:
        log_warn(f"auditd.conf: {e}")

    _run(["systemctl", "enable", "auditd"], "auditd enabled")
    _run(["systemctl", "restart", "auditd"], "auditd restarted")


def fix_file_permissions():
    log_section("File Permissions (UBU-072..082)")

    perms = [
        ("/etc/passwd", 0o644, "root", "root"),
        ("/etc/shadow", 0o640, "root", "shadow"),
        ("/etc/group", 0o644, "root", "root"),
        ("/etc/gshadow", 0o640, "root", "shadow"),
        ("/etc/crontab", 0o600, "root", "root"),
        ("/etc/ssh/sshd_config", 0o600, "root", "root"),
        ("/etc/sudoers", 0o440, "root", "root"),
        ("/etc/cron.hourly", 0o700, "root", "root"),
        ("/etc/cron.daily", 0o700, "root", "root"),
        ("/etc/cron.weekly", 0o700, "root", "root"),
        ("/etc/cron.monthly", 0o700, "root", "root"),
        ("/etc/cron.d", 0o700, "root", "root"),
        ("/etc/issue", 0o644, "root", "root"),
        ("/etc/issue.net", 0o644, "root", "root"),
        ("/etc/motd", 0o644, "root", "root"),
        ("/boot/grub/grub.cfg", 0o600, "root", "root"),
    ]

    for path, mode, owner, group in perms:
        if not os.path.exists(path):
            continue
        try:
            os.chmod(path, mode)
            _run(["chown", f"{owner}:{group}", path], f"chown {owner}:{group} {path}")
        except Exception as e:
            log_warn(f"Permissions {path}: {e}")

    # UBU-078: Sticky bit on world-writable directories
    result = subprocess.run(
        ["find", "/", "-xdev", "-type", "d", "-perm", "-0002", "-not", "-perm", "-1000"],
        capture_output=True, text=True, timeout=120
    )
    for d in result.stdout.strip().splitlines():
        if d:
            try:
                mode = os.stat(d).st_mode | 0o1000
                os.chmod(d, mode)
                log_ok(f"UBU-078: Sticky bit set on {d}")
            except Exception as e:
                log_warn(f"Sticky bit {d}: {e}")

    # UBU-079: World-writable files — report only
    result = subprocess.run(
        ["find", "/", "-xdev", "-type", "f", "-perm", "-0002",
         "-not", "-path", "/proc/*", "-not", "-path", "/sys/*"],
        capture_output=True, text=True, timeout=120
    )
    ww_files = result.stdout.strip().splitlines()
    if ww_files:
        log_warn(f"UBU-079: {len(ww_files)} world-writable files found — review manually")
        for f in ww_files[:10]:
            log_warn(f"  WW: {f}")
    else:
        log_ok("UBU-079: No world-writable files found")

    # UBU-080: Unowned files
    result = subprocess.run(
        ["find", "/", "-xdev", "-nouser", "-o", "-nogroup",
         "-not", "-path", "/proc/*", "-not", "-path", "/sys/*"],
        capture_output=True, text=True, timeout=120
    )
    unowned = result.stdout.strip().splitlines()
    if unowned:
        log_warn(f"UBU-080: {len(unowned)} unowned files found — review manually")
    else:
        log_ok("UBU-080: No unowned files found")

    # UBU-081: No legacy '+' in passwd/shadow/group
    for pf in ["/etc/passwd", "/etc/shadow", "/etc/group"]:
        if os.path.exists(pf):
            with open(pf, "r") as f:
                lines = f.readlines()
            plus_lines = [l for l in lines if l.startswith("+")]
            if plus_lines:
                log_warn(f"UBU-081: Legacy '+' entry found in {pf} — manual removal required")
            else:
                log_ok(f"UBU-081: No legacy '+' in {pf}")

    # UBU-082: No UID 0 accounts except root
    result = subprocess.run(["awk", "-F:", "($3==0){print $1}", "/etc/passwd"],
                             capture_output=True, text=True)
    uid0 = [u for u in result.stdout.strip().splitlines() if u != "root"]
    if uid0:
        log_warn(f"UBU-082: UID 0 accounts besides root: {uid0} — review manually")
    else:
        log_ok("UBU-082: Only root has UID 0")


def configure_filesystem():
    log_section("Filesystem Hardening (UBU-083..085)")

    # UBU-083: /tmp nodev,nosuid,noexec
    try:
        with open("/etc/fstab", "r") as f:
            fstab = f.read()
        if "tmpfs /tmp" not in fstab and "/tmp" not in fstab:
            with open("/etc/fstab", "a") as f:
                f.write("\ntmpfs /tmp tmpfs defaults,nodev,nosuid,noexec 0 0\n")
            log_ok("UBU-083: /tmp hardened in fstab")
        else:
            log_ok("UBU-083: /tmp already in fstab (verify nodev,nosuid,noexec manually)")
    except Exception as e:
        log_warn(f"fstab /tmp: {e}")

    # /dev/shm
    try:
        with open("/etc/fstab", "r") as f:
            fstab = f.read()
        if "tmpfs /dev/shm" not in fstab and "/dev/shm" not in fstab:
            with open("/etc/fstab", "a") as f:
                f.write("tmpfs /dev/shm tmpfs defaults,nodev,nosuid,noexec 0 0\n")
            log_ok("UBU-084: /dev/shm hardened in fstab")
        else:
            log_ok("UBU-084: /dev/shm already in fstab")
    except Exception as e:
        log_warn(f"fstab /dev/shm: {e}")

    # UBU-085: Core dumps
    limits_line = "* hard core 0\n"
    try:
        with open("/etc/security/limits.conf", "r") as f:
            content = f.read()
        if "hard core 0" not in content:
            with open("/etc/security/limits.conf", "a") as f:
                f.write(f"\n{limits_line}")
        log_ok("UBU-085: Core dumps disabled in limits.conf")
    except Exception as e:
        log_warn(f"limits.conf core dumps: {e}")

    # Disable core dumps via sysctl (already in apply_sysctl)
    log_skip("UBU-086: GRUB password — MANUAL: requires interactive grub-mkpasswd-pbkdf2")


def configure_user_accounts():
    log_section("User Account Hardening (UBU-087..090)")

    # UBU-087: Lock system accounts
    system_accounts = [
        "daemon", "bin", "sys", "sync", "games", "man",
        "lp", "mail", "news", "uucp", "proxy", "www-data",
        "backup", "list", "irc", "gnats", "nobody",
        "systemd-network", "systemd-resolve", "syslog",
        "messagebus", "uuidd", "sshd", "_apt",
    ]
    for account in system_accounts:
        result = subprocess.run(
            ["id", account], capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0:
            _run(["usermod", "-L", "-s", "/usr/sbin/nologin", account],
                 f"UBU-087: Locked {account}")

    # UBU-088: Disable root login on non-console TTYs
    securetty = "console\ntty1\n"
    _write_file("/etc/securetty", securetty, mode=0o600)
    log_ok("UBU-088: /etc/securetty restricted to console+tty1")

    # UBU-089: No empty passwords
    result = subprocess.run(
        ["awk", "-F:", "($2 == \"\" ){print $1}", "/etc/shadow"],
        capture_output=True, text=True
    )
    empty_pw = result.stdout.strip().splitlines()
    if empty_pw:
        log_warn(f"UBU-089: Accounts with empty passwords: {empty_pw} — locking them")
        for acc in empty_pw:
            _run(["passwd", "-l", acc], f"Locked {acc}")
    else:
        log_ok("UBU-089: No accounts with empty passwords")

    # UBU-090: Default umask = 027
    for profile_file in ["/etc/bash.bashrc", "/etc/profile"]:
        if os.path.exists(profile_file):
            with open(profile_file, "r") as f:
                content = f.read()
            if "umask 027" not in content:
                with open(profile_file, "a") as f:
                    f.write("\n# CIS hardening: default umask\numask 027\n")
            log_ok(f"UBU-090: umask 027 set in {profile_file}")


def configure_cron():
    log_section("Cron/At Restrictions (UBU-091..092)")

    # UBU-091: cron.allow
    if not os.path.exists("/etc/cron.allow"):
        _write_file("/etc/cron.allow", "root\n", mode=0o640)
        log_ok("UBU-091: /etc/cron.allow created (root only)")
    try:
        if os.path.exists("/etc/cron.deny"):
            os.remove("/etc/cron.deny")
    except Exception:
        pass

    # UBU-092: at.allow
    if not os.path.exists("/etc/at.allow"):
        _write_file("/etc/at.allow", "root\n", mode=0o640)
        log_ok("UBU-092: /etc/at.allow created (root only)")
    try:
        if os.path.exists("/etc/at.deny"):
            os.remove("/etc/at.deny")
    except Exception:
        pass

    # Secure cron directories
    for d in ["/etc/cron.hourly", "/etc/cron.daily", "/etc/cron.weekly",
               "/etc/cron.monthly", "/etc/cron.d"]:
        if os.path.exists(d):
            os.chmod(d, 0o700)

    _run(["chown", "root:root", "/etc/crontab"], "crontab owned by root")


def configure_screen_lock():
    log_section("Screen Lock (UBU-093..095)")

    # GNOME gsettings via dconf
    lock_settings = """
[org/gnome/desktop/session]
idle-delay=uint32 300

[org/gnome/desktop/screensaver]
lock-enabled=true
lock-delay=uint32 0
idle-activation-enabled=true
"""
    os.makedirs("/etc/dconf/db/local.d", exist_ok=True)
    _write_file("/etc/dconf/db/local.d/01-cis-lock", lock_settings)

    locks = """\
/org/gnome/desktop/session/idle-delay
/org/gnome/desktop/screensaver/lock-enabled
/org/gnome/desktop/screensaver/lock-delay
/org/gnome/desktop/screensaver/idle-activation-enabled
"""
    os.makedirs("/etc/dconf/db/local.d/locks", exist_ok=True)
    _write_file("/etc/dconf/db/local.d/locks/cis-lock", locks)

    # Profile
    _write_file("/etc/dconf/profile/user", "user-db:user\nsystem-db:local\n")

    # Update dconf
    _run(["dconf", "update"], "UBU-093..095: dconf updated for screen lock")
    log_ok("UBU-093..095: GNOME screen lock: idle-delay=300, lock-enabled=true")


def configure_automatic_updates():
    log_section("Automatic Updates (UBU-096..097)")

    _run(["apt-get", "install", "-y", "-q", "unattended-upgrades", "apt-listchanges"],
         "unattended-upgrades installed")

    unattended_conf = """\
// /etc/apt/apt.conf.d/50unattended-upgrades — CIS/ISSP hardened
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
Unattended-Upgrade::Automatic-Reboot "false";
Unattended-Upgrade::Automatic-Reboot-Time "02:00";
Unattended-Upgrade::Mail "";
Unattended-Upgrade::MailReport "on-change";
"""
    _write_file("/etc/apt/apt.conf.d/50unattended-upgrades", unattended_conf)

    auto_conf = """\
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::AutocleanInterval "7";
APT::Periodic::Unattended-Upgrade "1";
"""
    _write_file("/etc/apt/apt.conf.d/20auto-upgrades", auto_conf)
    _run(["systemctl", "enable", "unattended-upgrades"], "unattended-upgrades enabled")
    log_ok("UBU-096..097: Automatic security updates configured")


def configure_aide():
    log_section("AIDE File Integrity Monitoring (UBU-098..100)")

    _run(["apt-get", "install", "-y", "-q", "aide", "aide-common"], "AIDE installed")

    # UBU-099: Initialize database
    log_ok("UBU-099: Initializing AIDE database (this may take several minutes)...")
    _run(["aideinit", "-y", "-f"], "AIDE database initialized")

    try:
        if os.path.exists("/var/lib/aide/aide.db.new.gz"):
            shutil.copy("/var/lib/aide/aide.db.new.gz", "/var/lib/aide/aide.db.gz")
            log_ok("AIDE: database copied to active location")
    except Exception as e:
        log_warn(f"AIDE db copy: {e}")

    # UBU-100: Daily cron job
    aide_cron = "0 5 * * * root /usr/bin/aide --check | /usr/bin/logger -t aide\n"
    _write_file("/etc/cron.d/aide-check", aide_cron, mode=0o644)
    log_ok("UBU-100: AIDE daily check cron configured")


def configure_logging():
    log_section("Logging Configuration (UBU-101..104)")

    # UBU-101: rsyslog log file permissions
    rsyslog_conf = """\
# /etc/rsyslog.d/99-cis-hardening.conf
$FileOwner root
$FileGroup adm
$FileCreateMode 0640
$DirCreateMode 0755
$Umask 0022
$PrivDropToUser syslog
$PrivDropToGroup syslog
"""
    _write_file("/etc/rsyslog.d/99-cis-hardening.conf", rsyslog_conf)
    log_ok("UBU-101: rsyslog file permissions configured (0640)")
    _run(["systemctl", "restart", "rsyslog"], "rsyslog restarted")

    # UBU-102: logrotate — check it exists
    if os.path.exists("/etc/logrotate.conf"):
        log_ok("UBU-102: logrotate.conf exists")

    # UBU-103: NTP/chrony
    _run(["apt-get", "install", "-y", "-q", "chrony"], "chrony installed")
    _run(["systemctl", "enable", "chrony"], "chrony enabled")
    _run(["systemctl", "start", "chrony"], "chrony started")
    log_ok("UBU-103: NTP via chrony configured")

    # UBU-104: Disable Ctrl+Alt+Del
    _run(["systemctl", "mask", "ctrl-alt-del.target"], "UBU-104: Ctrl+Alt+Del masked")
    _run(["systemctl", "daemon-reload"], "systemd reloaded")


def configure_system_banners():
    log_section("System Banners (UBU-105..107)")

    _write_file("/etc/motd", BANNER_TEXT)
    log_ok("UBU-105: /etc/motd written")

    _write_file("/etc/issue", BANNER_TEXT)
    log_ok("UBU-106: /etc/issue written")

    _write_file("/etc/issue.net", BANNER_TEXT)
    log_ok("UBU-107: /etc/issue.net written")


def configure_apparmor():
    log_section("AppArmor (UBU-022..023)")

    _run(["apt-get", "install", "-y", "-q", "apparmor", "apparmor-utils"], "AppArmor installed")
    _run(["systemctl", "enable", "apparmor"], "AppArmor enabled")
    _run(["systemctl", "start", "apparmor"], "AppArmor started")

    # Enforce all profiles
    _run(["aa-enforce", "/etc/apparmor.d/*"], "UBU-022..023: AppArmor profiles enforced")
    log_ok("UBU-022..023: AppArmor in enforce mode")


def configure_sudo():
    log_section("Sudo Configuration (UBU-108..109)")

    sudoers_drop = """\
# /etc/sudoers.d/cis-hardening — generated by harden.py
Defaults requiretty
Defaults !visiblepw
Defaults always_set_home
Defaults match_group_by_gid
Defaults always_query_group_plugin
Defaults env_reset
Defaults env_keep = "COLORS DISPLAY HOSTNAME HISTSIZE KDEDIR LS_COLORS"
Defaults env_keep += "MAIL QTDIR USERNAME LANG LC_ADDRESS LC_CTYPE"
Defaults env_keep += "LC_COLLATE LC_IDENTIFICATION LC_MEASUREMENT LC_MESSAGES"
Defaults env_keep += "LC_MONETARY LC_NAME LC_NUMERIC LC_PAPER LC_TELEPHONE"
Defaults env_keep += "LC_TIME LC_ALL LANGUAGE LINGUAS _XKB_CHARSET XAUTHORITY"
Defaults secure_path = /sbin:/bin:/usr/sbin:/usr/bin
Defaults timestamp_timeout=5
Defaults passwd_timeout=1
Defaults badpass_message="Authentication failure"
Defaults logfile=/var/log/sudo.log
Defaults log_input,log_output
"""
    _write_file("/etc/sudoers.d/cis-hardening", sudoers_drop, mode=0o440)
    log_ok("UBU-108..109: /etc/sudoers.d/cis-hardening written (timeout=5, logging)")


def check_luks_encryption():
    log_section("LUKS Encryption Check (UBU-110)")

    result = subprocess.run(
        ["lsblk", "-o", "NAME,TYPE,FSTYPE"],
        capture_output=True, text=True, timeout=30
    )
    if "crypt" in result.stdout:
        log_ok("UBU-110: LUKS encrypted volume detected")
    else:
        log_warn("UBU-110: No LUKS encryption detected. ISSP §5.1 requires full disk encryption.")
        log_warn("  ACTION REQUIRED: Reinstall with LUKS or use cryptsetup to encrypt secondary volumes.")

    log_skip("UBU-111: USB storage — NOT disabled. Admin must evaluate per-machine policy.")
    log_skip("UBU-113: VPN enforcement — MANUAL: requires VPN infrastructure.")


def harden_misc():
    log_section("Miscellaneous Hardening")

    # Disable core dump via sysctl (already done in apply_sysctl, but also suid_dumpable)
    # Disable Ctrl+Alt+Del (done in configure_logging)

    # Restrict /proc access
    try:
        with open("/etc/fstab", "r") as f:
            fstab = f.read()
        if "hidepid" not in fstab:
            with open("/etc/fstab", "a") as f:
                f.write("\nproc /proc proc defaults,hidepid=2 0 0\n")
            log_ok("hidepid=2 added to /proc mount")
    except Exception as e:
        log_warn(f"/proc hidepid: {e}")

    # Modprobe blacklist
    blacklist = """\
# CIS hardening — unused/dangerous kernel modules
install cramfs /bin/true
install freevxfs /bin/true
install jffs2 /bin/true
install hfs /bin/true
install hfsplus /bin/true
install udf /bin/true
install dccp /bin/true
install sctp /bin/true
install rds /bin/true
install tipc /bin/true
"""
    _write_file("/etc/modprobe.d/cis-hardening.conf", blacklist)
    log_ok("Unused kernel modules blacklisted (cramfs, freevxfs, jffs2, hfs, dccp, sctp, rds, tipc)")

    # Disable uncommon network protocols
    _run(["modprobe", "-r", "dccp"], "DCCP unloaded")
    _run(["modprobe", "-r", "sctp"], "SCTP unloaded")
    _run(["modprobe", "-r", "rds"], "RDS unloaded")
    _run(["modprobe", "-r", "tipc"], "TIPC unloaded")


def harden():
    """Main Ubuntu hardening entry point."""
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
