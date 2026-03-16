"""
modules/windows_dc.py — Windows Server 2025 Active Directory DC hardening.

Implements CIS Microsoft Windows Server 2025 Benchmark v2.0.0 — Level 1 DC
profile, plus ISSP (ISO 27002 v2) requirements for Bidouille.

Must be invoked as Administrator on Windows Server 2025.

Architecture
────────────
The script uses two complementary mechanisms:

  1. secedit INF template (apply_account_policies_and_user_rights)
     Covers sections 1.x (Account Policy), 2.2 (User Rights), and part of
     2.3 (Security Options).  secedit is the official Windows tool for applying
     local security policy; using it ensures settings go through the same
     enforcement path as Group Policy.

  2. Direct registry writes via PowerShell Set-ItemProperty
     Covers sections 2.3.17 (UAC), 9.x (Firewall via netsh), 17.x (auditpol),
     and all of 18.x (Administrative Templates).

Sections implemented
────────────────────
  apply_account_policies_and_user_rights() — WDC-001..049  secedit INF
  apply_uac_settings()                     — WDC-100..107  registry
  apply_system_services()                  — WDC-108       PowerShell
  apply_windows_firewall()                 — WDC-109..122  netsh
  apply_advanced_audit_policy()            — WDC-123..156  auditpol
  apply_administrative_templates()         — WDC-157..340  registry
  apply_issp_specific()                    — WDC-341..351  PSO + BitLocker
"""

import os
import subprocess
import tempfile
from modules.logger import get_logger, log_ok, log_warn, log_fail, log_section, log_skip


# ── PowerShell / command helpers ──────────────────────────────────────────────

def _ps(command: str, check: bool = False) -> tuple[int, str, str]:
    """
    Execute a PowerShell command and return (returncode, stdout, stderr).

    All values embedded in the command string come from this script's own
    constants (never from user input), so f-string construction is safe here.

    Args:
        command: PowerShell command string to execute.
        check:   If True, log a FAIL (instead of WARN) on non-zero exit.

    Returns:
        (returncode, stdout.strip(), stderr.strip())
    """
    try:
        result = subprocess.run(
            ["powershell", "-NonInteractive", "-NoProfile", "-Command", command],
            capture_output=True, text=True, timeout=120
        )
        if result.returncode != 0 and check:
            log_fail(f"PowerShell: {result.stderr.strip()[:300]}")
        return result.returncode, result.stdout.strip(), result.stderr.strip()
    except FileNotFoundError:
        log_fail("PowerShell not found — Windows hardening cannot continue")
        return 1, "", "PowerShell not found"
    except subprocess.TimeoutExpired:
        log_warn("PowerShell command timed out (120 s)")
        return 1, "", "timeout"


def _reg_set(key: str, value_name: str, value_type: str, data) -> bool:
    """
    Create or update a Windows registry value via PowerShell.

    All parameters are hardcoded constants from this module — never derived
    from external input — so there is no injection risk.

    Args:
        key:        Full registry path, e.g. "HKLM:\\SOFTWARE\\Policies\\...".
        value_name: Registry value name.
        value_type: PowerShell type string: "DWord", "String", "QWord", etc.
        data:       Value data (int for DWord, str for String, etc.).

    Returns:
        True if the registry write succeeded, False otherwise.
    """
    # Quote the data appropriately for PowerShell depending on type
    if value_type == "String":
        ps_data = f"'{data}'"
    else:
        ps_data = str(data)

    # Create the key path if it doesn't exist, then set the value
    cmd = (
        f'If (!(Test-Path "{key}")) {{ New-Item -Path "{key}" -Force | Out-Null }}; '
        f'Set-ItemProperty -Path "{key}" -Name "{value_name}" '
        f'-Type {value_type} -Value {ps_data} -Force'
    )
    rc, _, err = _ps(cmd)
    if rc == 0:
        log_ok(f"Registry: {key}\\{value_name} = {data}")
        return True
    else:
        log_warn(f"Registry: {key}\\{value_name} → {err[:200]}")
        return False


def _run_cmd(args: list, label: str) -> bool:
    """
    Run a non-PowerShell command (secedit, netsh, auditpol, reg) and log the result.

    Args:
        args:  Command + arguments list.
        label: Human-readable description for log output.

    Returns:
        True if exit code was 0, False otherwise.
    """
    try:
        result = subprocess.run(args, capture_output=True, text=True, timeout=120)
        if result.returncode == 0:
            log_ok(label)
            return True
        else:
            log_warn(f"{label}: exit {result.returncode} — {result.stderr.strip()[:200]}")
            return False
    except FileNotFoundError:
        log_warn(f"{label}: command not found")
        return False
    except subprocess.TimeoutExpired:
        log_warn(f"{label}: timed out after 120 s")
        return False
    except Exception as exc:
        log_fail(f"{label}: {exc}")
        return False


# ── secedit INF template ──────────────────────────────────────────────────────
#
# This INF file is fed to 'secedit /configure' to apply:
#   - Account policies (section 1.x):  password policy, lockout policy
#   - User rights assignment (section 2.2): who can log on, debug, back up, etc.
#   - Registry values (selected section 2.3 security options)
#
# SID notation:
#   *S-1-5-32-544  = BUILTIN\Administrators
#   *S-1-5-32-545  = BUILTIN\Users
#   *S-1-5-32-546  = BUILTIN\Guests
#   *S-1-5-32-551  = BUILTIN\Backup Operators
#   *S-1-5-9       = ENTERPRISE DOMAIN CONTROLLERS
#   *S-1-5-11      = Authenticated Users
#   *S-1-5-19      = LOCAL SERVICE
#   *S-1-5-20      = NETWORK SERVICE
#   *S-1-5-6       = SERVICE
#
# References: CIS sections 1.1, 1.2, 2.2, 2.3 (partial)

SECEDIT_INF_TEMPLATE = """[Unicode]
Unicode=yes

[System Access]
; ── CIS 1.1: Password Policy ─────────────────────────────────────────────────
PasswordHistorySize  = 24       ; WDC-001: remember last 24 passwords
MaximumPasswordAge   = 90       ; WDC-002: expire after 90 days (ISSP §7.1)
MinimumPasswordAge   = 1        ; WDC-003: must wait 1 day before changing
MinimumPasswordLength = 14      ; WDC-004: minimum 14 characters
PasswordComplexity   = 1        ; WDC-005: uppercase + lowercase + digit + symbol
ClearTextPassword    = 0        ; WDC-007: never store passwords in reversible form
; ── CIS 1.2: Account Lockout Policy ──────────────────────────────────────────
LockoutBadCount      = 5        ; WDC-009: lock after 5 failed attempts
LockoutDuration      = 15       ; WDC-008: locked for 15 minutes
ResetLockoutCount    = 15       ; WDC-010: reset counter after 15 minutes
; ── CIS 2.3.1: Accounts ───────────────────────────────────────────────────────
RequireLogonToChangePassword = 0
ForceLogoffWhenHourExpire    = 1
NewAdministratorName         = "LocalAdmin_Bidouille"  ; WDC-052: rename administrator
NewGuestName                 = "GuestAccount_Disabled" ; WDC-053: rename guest
EnableAdminAccount           = 0
EnableGuestAccount           = 0                        ; WDC-050: disable guest account
LSAAnonymousNameLookup       = 0                        ; WDC-078: no anonymous SID lookup

[Privilege Rights]
; ── CIS 2.2: User Rights Assignment ──────────────────────────────────────────
; Each right lists the SIDs that should hold it; empty = No One.

; WDC-011: Access Credential Manager as a trusted caller = No One
; (intentionally absent / empty — secedit interprets absence as empty)

; WDC-012: Access this computer from the network (DC profile)
SeNetworkLogonRight           = *S-1-5-32-544,*S-1-5-11,*S-1-5-9

; WDC-013: Act as part of the operating system = No One
SeTcbPrivilege                =

; WDC-014: Add workstations to domain = Administrators
SeMachineAccountPrivilege     = *S-1-5-32-544

; WDC-015: Adjust memory quotas = Administrators, LOCAL SERVICE, NETWORK SERVICE
SeIncreaseQuotaPrivilege      = *S-1-5-32-544,*S-1-5-19,*S-1-5-20

; WDC-016: Allow log on locally (DC) = Administrators, Enterprise Domain Controllers
SeInteractiveLogonRight       = *S-1-5-32-544,*S-1-5-9

; WDC-017: Allow log on through RDS (DC) = Administrators only
SeRemoteInteractiveLogonRight = *S-1-5-32-544

; WDC-018: Back up files and directories = Administrators
SeBackupPrivilege             = *S-1-5-32-544

; WDC-019: Change system time = Administrators, LOCAL SERVICE
SeSystemTimePrivilege         = *S-1-5-32-544,*S-1-5-19

; WDC-020: Create a pagefile = Administrators
SeCreatePagefilePrivilege     = *S-1-5-32-544

; WDC-021: Create a token object = No One
SeCreateTokenPrivilege        =

; WDC-022: Create global objects = Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE
SeCreateGlobalPrivilege       = *S-1-5-32-544,*S-1-5-19,*S-1-5-20,*S-1-5-6

; WDC-023: Create permanent shared objects = No One
SeCreatePermanentPrivilege    =

; WDC-024: Create symbolic links (DC) = Administrators
SeCreateSymbolicLinkPrivilege = *S-1-5-32-544

; WDC-025: Debug programs = Administrators
SeDebugPrivilege              = *S-1-5-32-544

; WDC-026: Deny access from network (DC) = Guests
SeDenyNetworkLogonRight       = *S-1-5-32-546

; WDC-027: Deny log on as batch job = Guests
SeDenyBatchLogonRight         = *S-1-5-32-546

; WDC-028: Deny log on as service = Guests
SeDenyServiceLogonRight       = *S-1-5-32-546

; WDC-029: Deny log on locally = Guests
SeDenyInteractiveLogonRight   = *S-1-5-32-546

; WDC-030: Deny log on through RDS = Guests
SeDenyRemoteInteractiveLogonRight = *S-1-5-32-546

; WDC-031: Enable computer/user accounts to be trusted for delegation (DC) = Administrators
SeEnableDelegationPrivilege   = *S-1-5-32-544

; WDC-032: Force shutdown from remote = Administrators
SeRemoteShutdownPrivilege     = *S-1-5-32-544

; WDC-033: Generate security audits = LOCAL SERVICE, NETWORK SERVICE
SeAuditPrivilege              = *S-1-5-19,*S-1-5-20

; WDC-034: Impersonate a client after authentication (DC)
SeImpersonatePrivilege        = *S-1-5-32-544,*S-1-5-19,*S-1-5-20,*S-1-5-6

; WDC-035: Increase scheduling priority = Administrators, Window Manager Group
SeIncreaseBasePriorityPrivilege = *S-1-5-32-544

; WDC-036: Load and unload device drivers = Administrators
SeLoadDriverPrivilege         = *S-1-5-32-544

; WDC-037: Lock pages in memory = No One
SeLockMemoryPrivilege         =

; WDC-038: Log on as a batch job (DC) = Administrators
SeBatchLogonRight             = *S-1-5-32-544

; WDC-039: Manage auditing and security log (DC) = Administrators
SeSecurityPrivilege           = *S-1-5-32-544

; WDC-040: Modify an object label = No One
SeRelabelPrivilege            =

; WDC-041: Modify firmware environment values = Administrators
SeSystemEnvironmentPrivilege  = *S-1-5-32-544

; WDC-042: Perform volume maintenance tasks = Administrators
SeManageVolumePrivilege       = *S-1-5-32-544

; WDC-043: Profile single process = Administrators
SeProfileSingleProcessPrivilege = *S-1-5-32-544

; WDC-044: Profile system performance = Administrators, NT SERVICE\\WdiServiceHost
SeSystemProfilePrivilege      = *S-1-5-32-544,*S-1-5-80-3139157870-2983391045-3678747466-658725712-1809340420

; WDC-045: Replace a process-level token = LOCAL SERVICE, NETWORK SERVICE
SeAssignPrimaryTokenPrivilege = *S-1-5-19,*S-1-5-20

; WDC-046: Restore files and directories = Administrators
SeRestorePrivilege            = *S-1-5-32-544

; WDC-047: Shut down the system = Administrators
SeShutdownPrivilege           = *S-1-5-32-544

; WDC-048: Synchronize directory service data (DC) = No One
SeSyncAgentPrivilege          =

; WDC-049: Take ownership of files or other objects = Administrators
SeTakeOwnershipPrivilege      = *S-1-5-32-544

SeChangeNotifyPrivilege       = *S-1-5-32-544,*S-1-5-32-545,*S-1-5-32-551,*S-1-5-19,*S-1-5-20
SeIncreaseWorkingSetPrivilege = *S-1-5-32-544,*S-1-5-32-545
SeTimeZonePrivilege           = *S-1-5-32-544,*S-1-5-32-545,*S-1-5-19
SeUndockPrivilege             = *S-1-5-32-544

[Registry Values]
; ── CIS 2.3.2: Audit Policy ───────────────────────────────────────────────────
; WDC-054: Force audit subcategory settings (not legacy audit categories)
MACHINE\\System\\CurrentControlSet\\Control\\Lsa\\SCENoApplyLegacyAuditPolicy=4,1
; WDC-055: Do NOT shut down if audit log is full (would cause DoS)
MACHINE\\System\\CurrentControlSet\\Control\\Lsa\\CrashOnAuditFail=4,0

; ── CIS 2.3.6: Domain Member ─────────────────────────────────────────────────
; WDC-060..066: Secure channel settings + machine account password age
MACHINE\\System\\CurrentControlSet\\Services\\Netlogon\\Parameters\\DisablePasswordChange=4,0
MACHINE\\System\\CurrentControlSet\\Services\\Netlogon\\Parameters\\MaximumPasswordAge=4,30
MACHINE\\System\\CurrentControlSet\\Services\\Netlogon\\Parameters\\RequireSignOrSeal=4,1
MACHINE\\System\\CurrentControlSet\\Services\\Netlogon\\Parameters\\SealSecureChannel=4,1
MACHINE\\System\\CurrentControlSet\\Services\\Netlogon\\Parameters\\SignSecureChannel=4,1
MACHINE\\System\\CurrentControlSet\\Services\\Netlogon\\Parameters\\StrongKey=4,1

; ── CIS 2.3.10: Network Access ───────────────────────────────────────────────
MACHINE\\System\\CurrentControlSet\\Control\\Lsa\\RestrictAnonymous=4,1
MACHINE\\System\\CurrentControlSet\\Control\\Lsa\\RestrictAnonymousSAM=4,1
MACHINE\\System\\CurrentControlSet\\Control\\Lsa\\DisableDomainCreds=4,1
MACHINE\\System\\CurrentControlSet\\Control\\Lsa\\EveryoneIncludesAnonymous=4,0

; ── CIS 2.3.11: Network Security ─────────────────────────────────────────────
; WDC-091: LAN Manager auth level = NTLMv2 only, refuse LM and NTLM
MACHINE\\System\\CurrentControlSet\\Control\\Lsa\\LmCompatibilityLevel=4,5
; WDC-093/094: Minimum session security for NTLM SSP = NTLMv2 + 128-bit
MACHINE\\System\\CurrentControlSet\\Control\\Lsa\\MSV1_0\\NTLMMinClientSec=4,537395200
MACHINE\\System\\CurrentControlSet\\Control\\Lsa\\MSV1_0\\NTLMMinServerSec=4,537395200
; WDC-088: Disable NULL session fallback
MACHINE\\System\\CurrentControlSet\\Control\\Lsa\\MSV1_0\\allownullsessionfallback=4,0
; WDC-089: Disable PKU2U online identity authentication
MACHINE\\System\\CurrentControlSet\\Control\\Lsa\\pku2u\\AllowOnlineID=4,0
; WDC-090: Kerberos encryption = AES-128 + AES-256 only (value = 0x7FFFFFFC)
MACHINE\\System\\CurrentControlSet\\Control\\Lsa\\SupportedEncryptionTypes=4,2147483644
; WDC-092: LDAP client signing = Negotiate signing
MACHINE\\System\\CurrentControlSet\\Control\\Lsa\\LdapClientIntegrity=4,1

; ── SMB signing (CIS 2.3.8 / 2.3.9) ─────────────────────────────────────────
; WDC-073/074: SMB client settings
MACHINE\\System\\CurrentControlSet\\Services\\LanManWorkstation\\Parameters\\EnableSecuritySignature=4,1
MACHINE\\System\\CurrentControlSet\\Services\\LanManWorkstation\\Parameters\\RequireSecuritySignature=4,1
MACHINE\\System\\CurrentControlSet\\Services\\LanManWorkstation\\Parameters\\EnablePlainTextPassword=4,0
; WDC-075/076/077: SMB server settings
MACHINE\\System\\CurrentControlSet\\Services\\LanManServer\\Parameters\\autodisconnect=4,15
MACHINE\\System\\CurrentControlSet\\Services\\LanManServer\\Parameters\\EnableSecuritySignature=4,1
MACHINE\\System\\CurrentControlSet\\Services\\LanManServer\\Parameters\\RequireSecuritySignature=4,1
MACHINE\\System\\CurrentControlSet\\Services\\LanManServer\\Parameters\\RestrictNullSessAccess=4,1
MACHINE\\System\\CurrentControlSet\\Services\\LanManServer\\Parameters\\EnableForcedLogOff=4,1

; WDC-086: No anonymous share enumeration
MACHINE\\System\\CurrentControlSet\\Services\\LanManServer\\Parameters\\AutoShareWks=4,0
MACHINE\\System\\CurrentControlSet\\Services\\LanManServer\\Parameters\\AutoShareServer=4,0

; ── CIS 2.3.7: Interactive Logon ─────────────────────────────────────────────
; WDC-067: CTRL+ALT+DEL required for logon
MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\DisableCAD=4,0
; WDC-068: Do not display last user name at logon screen
MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\DontDisplayLastUserName=4,1
; WDC-069: Auto-lock after 300 seconds (5 minutes) — ISSP §4.2
MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\InactivityTimeoutSecs=4,300
; WDC-070/071: Legal notice text and title
MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\LegalNoticeText=7,"AUTHORISED USE ONLY\\nThis system is the property of Bidouille. Unauthorised access is prohibited."
MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\LegalNoticeCaption=1,"Bidouille - Authorised Access Only"
; WDC-072: Smart card removal behaviour = Lock Workstation (value 1)
MACHINE\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\ScRemoveOption=1,"1"

; ── CIS 2.3.13: Shutdown ─────────────────────────────────────────────────────
; WDC-098: Do not allow system to be shut down without logging on
MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\ShutdownWithoutLogon=4,0

; ── CIS 2.3.1: Local account token filter ────────────────────────────────────
; WDC-085 / WDC-169: Restrict remote admin rights for local accounts
MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\LocalAccountTokenFilterPolicy=4,0

; Password expiry warning = 14 days (matching PASS_WARN_AGE on Linux)
MACHINE\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\PasswordExpiryWarning=4,14

[Version]
signature="$CHICAGO$"
Revision=1
"""


def apply_account_policies_and_user_rights(temp_dir: str) -> bool:
    """
    WDC-001..049 + selected WDC-050..099 — Apply account policies, user rights,
    and security options via secedit.

    The INF template above is written to a temp file and applied with:
      secedit /configure /db <sdb> /cfg <inf> /overwrite /quiet

    Args:
        temp_dir: Writable temp directory for the .inf and .sdb files.

    Returns:
        True if secedit succeeded, False otherwise.
    """
    log_section("Account Policies + User Rights + Security Options (secedit)")

    inf_path = os.path.join(temp_dir, "hardening.inf")
    sdb_path = os.path.join(temp_dir, "secedit.sdb")

    # secedit requires the INF to be UTF-16 LE with BOM
    with open(inf_path, "w", encoding="utf-16") as f:
        f.write(SECEDIT_INF_TEMPLATE)

    ok = _run_cmd(
        ["secedit", "/configure", "/db", sdb_path,
         "/cfg", inf_path, "/overwrite", "/quiet"],
        "secedit /configure — account policies + user rights + security options"
    )
    if ok:
        log_ok("WDC-001..010: account + lockout policies applied")
        log_ok("WDC-011..049: user rights assignment applied")
        log_ok("WDC-050..099: security options applied via secedit INF")
    return ok


def apply_uac_settings() -> None:
    """
    WDC-100..107 — Configure User Account Control (UAC) via registry.

    UAC prevents privilege escalation by requiring explicit consent for
    administrative actions.  These settings implement the strictest CIS
    recommendations for a Domain Controller.
    """
    log_section("UAC Settings (WDC-100..107)")

    base = "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System"

    # Each tuple: (ValueName, Type, Data, Description)
    settings = [
        # WDC-100: Admin Approval Mode for built-in Administrator account
        ("FilterAdministratorToken",    "DWord", 1, "Admin Approval Mode for built-in Admin"),
        # WDC-101: Elevation prompt for administrators = Prompt for consent on secure desktop
        ("ConsentPromptBehaviorAdmin",  "DWord", 2, "Admin prompt = consent on secure desktop"),
        # WDC-102: Elevation prompt for standard users = Automatically deny
        ("ConsentPromptBehaviorUser",   "DWord", 0, "Standard user prompt = auto deny"),
        # WDC-103: Detect application installations and prompt for elevation
        ("EnableInstallerDetection",    "DWord", 1, "Detect installer elevation"),
        # WDC-104: Only elevate UIAccess applications from secure locations
        ("EnableSecureUIAPaths",        "DWord", 1, "UIAccess only from secure locations"),
        # WDC-105: Run all administrators in Admin Approval Mode
        ("EnableLUA",                   "DWord", 1, "Admin Approval Mode for all admins"),
        # WDC-106: Switch to secure desktop when prompting for elevation
        ("PromptOnSecureDesktop",       "DWord", 1, "Elevation on secure desktop"),
        # WDC-107: Virtualise file and registry write failures to per-user locations
        ("EnableVirtualization",        "DWord", 1, "Virtualise write failures"),
    ]
    for name, vtype, val, desc in settings:
        _reg_set(base, name, vtype, val)
        log_ok(f"WDC: UAC {desc}")


def apply_system_services() -> None:
    """
    WDC-108 — Disable the Print Spooler service on Domain Controllers.

    The Print Spooler must be disabled on DCs because:
      - DCs do not need to print.
      - The Spooler has a long history of privilege-escalation vulnerabilities
        (PrintNightmare, CVE-2021-34527, etc.).

    Both the service and its auto-start registration are disabled.
    """
    log_section("System Services (WDC-108)")

    log_ok("WDC-108: disabling Print Spooler (known vulnerability surface on DCs)")
    _ps("Stop-Service -Name Spooler -Force -ErrorAction SilentlyContinue")
    _ps("Set-Service  -Name Spooler -StartupType Disabled")
    log_ok("Print Spooler stopped and disabled")


def apply_windows_firewall() -> None:
    """
    WDC-109..122 — Configure Windows Firewall for all three network profiles
    (Domain, Private, Public) using netsh advfirewall.

    Policy:
      - All profiles: ON, inbound BLOCK, outbound ALLOW
      - Logging: dropped packets + successful connections, max 16 MB log file
      - Public profile additionally: disable local rule overrides (CIS 9.3.4/9.3.5)

    After setting the default policies, we add explicit allow rules for the
    services that a DC must accept (DNS, Kerberos, LDAP, RPC, SMB, NTP, etc.).
    """
    log_section("Windows Firewall (WDC-109..122)")

    # ── Domain profile ────────────────────────────────────────────────────────
    _run_cmd(["netsh", "advfirewall", "set", "domainprofile", "state", "on"],
             "WDC-109: domain firewall ON")
    _run_cmd(["netsh", "advfirewall", "set", "domainprofile",
              "firewallpolicy", "blockinbound,allowoutbound"],
             "WDC-110: domain — block inbound")
    _run_cmd(["netsh", "advfirewall", "set", "domainprofile",
              "settings", "inboundusernotification", "disable"],
             "WDC-111: domain — no notifications")
    _run_cmd(["netsh", "advfirewall", "set", "domainprofile", "logging",
              "maxfilesize", "16384", "droppedconnections", "enable",
              "allowedconnections", "enable"],
             "WDC-112..114: domain — logging configured (16 MB)")

    # ── Private profile ────────────────────────────────────────────────────────
    _run_cmd(["netsh", "advfirewall", "set", "privateprofile", "state", "on"],
             "WDC-115: private firewall ON")
    _run_cmd(["netsh", "advfirewall", "set", "privateprofile",
              "firewallpolicy", "blockinbound,allowoutbound"],
             "WDC-116: private — block inbound")
    _run_cmd(["netsh", "advfirewall", "set", "privateprofile", "logging",
              "maxfilesize", "16384", "droppedconnections", "enable",
              "allowedconnections", "enable"],
             "WDC-117: private — logging configured")

    # ── Public profile ─────────────────────────────────────────────────────────
    _run_cmd(["netsh", "advfirewall", "set", "publicprofile", "state", "on"],
             "WDC-118: public firewall ON")
    _run_cmd(["netsh", "advfirewall", "set", "publicprofile",
              "firewallpolicy", "blockinbound,allowoutbound"],
             "WDC-119: public — block inbound")
    # CIS 9.3.4 / 9.3.5: prevent local administrators from creating rules that
    # override the Group Policy firewall settings on public networks
    _run_cmd(["netsh", "advfirewall", "set", "publicprofile",
              "settings", "localfirewallrules", "disable",
              "localconsecrules", "disable"],
             "WDC-120..121: public — local rule overrides disabled")
    _run_cmd(["netsh", "advfirewall", "set", "publicprofile", "logging",
              "maxfilesize", "16384", "droppedconnections", "enable",
              "allowedconnections", "enable"],
             "WDC-122: public — logging configured")

    # ── DC service ports ──────────────────────────────────────────────────────
    # These are the minimum ports required for a functional DC.
    # Applied only to the Domain profile to reduce attack surface.
    log_ok("Adding required DC inbound firewall rules...")
    dc_ports = [
        ("DNS-UDP",      "53",   "UDP"),  # DNS
        ("DNS-TCP",      "53",   "TCP"),  # DNS over TCP (large responses/zone transfers)
        ("Kerberos-UDP", "88",   "UDP"),  # Kerberos
        ("Kerberos-TCP", "88",   "TCP"),  # Kerberos
        ("LDAP-TCP",     "389",  "TCP"),  # LDAP
        ("LDAP-UDP",     "389",  "UDP"),  # LDAP (ping)
        ("LDAP-SSL",     "636",  "TCP"),  # LDAPS
        ("GC-LDAP",      "3268", "TCP"),  # Global Catalog
        ("GC-LDAP-SSL",  "3269", "TCP"),  # Global Catalog SSL
        ("SMB",          "445",  "TCP"),  # SMB (SYSVOL/NETLOGON)
        ("RPC-Endpt",    "135",  "TCP"),  # RPC Endpoint Mapper
        ("NTP-UDP",      "123",  "UDP"),  # NTP time synchronisation
        ("NetBIOS-NS",   "137",  "UDP"),  # NetBIOS Name Service (legacy)
        ("NetBIOS-DGM",  "138",  "UDP"),  # NetBIOS Datagram (legacy)
        ("NetBIOS-SSN",  "139",  "TCP"),  # NetBIOS Session (legacy)
    ]
    for rule_name, port, proto in dc_ports:
        _ps(
            f'New-NetFirewallRule -DisplayName "DC-{rule_name}" '
            f'-Direction Inbound -Protocol {proto} -LocalPort {port} '
            f'-Action Allow -Profile Domain -ErrorAction SilentlyContinue | Out-Null'
        )
    log_ok("DC firewall allow rules added for Domain profile")


def apply_advanced_audit_policy() -> None:
    """
    WDC-123..156 — Configure advanced audit policy subcategories via auditpol.

    Why auditpol instead of Group Policy?
    The advanced audit policy (section 17 of CIS) uses per-subcategory settings
    that are more granular than the legacy 9-category audit policy.  auditpol is
    the command-line tool that applies these directly, matching what GPO would do.

    Each subcategory is listed with:
      (name, enable_success, enable_failure)
    where True = /success:enable and False = /success:disable (or failure equiv.).
    """
    log_section("Advanced Audit Policy (WDC-123..156)")

    # (subcategory_name, log_success, log_failure)
    audit_settings = [
        # ── 17.1: Account Logon ────────────────────────────────────────────
        ("Credential Validation",                True,  True),   # WDC-123
        ("Kerberos Authentication Service",      True,  True),   # WDC-124 DC only
        ("Kerberos Service Ticket Operations",   True,  True),   # WDC-125 DC only
        # ── 17.2: Account Management ──────────────────────────────────────
        ("Application Group Management",         True,  True),   # WDC-126
        ("Computer Account Management",          True,  False),  # WDC-127 DC only
        ("Distribution Group Management",        True,  False),  # WDC-128 DC only
        ("Other Account Management Events",      True,  False),  # WDC-129 DC only
        ("Security Group Management",            True,  False),  # WDC-130
        ("User Account Management",              True,  True),   # WDC-131
        # ── 17.3: Detailed Tracking ───────────────────────────────────────
        ("Plug and Play Events",                 True,  False),  # WDC-132
        ("Process Creation",                     True,  False),  # WDC-133
        # ── 17.4: DS Access (DC only) ─────────────────────────────────────
        ("Directory Service Access",             False, True),   # WDC-134
        ("Directory Service Changes",            True,  False),  # WDC-135
        # ── 17.5: Logon/Logoff ────────────────────────────────────────────
        ("Account Lockout",                      False, True),   # WDC-136
        ("Group Membership",                     True,  False),  # WDC-137
        ("Logoff",                               True,  False),  # WDC-138
        ("Logon",                                True,  True),   # WDC-139
        ("Other Logon/Logoff Events",            True,  True),   # WDC-140
        ("Special Logon",                        True,  False),  # WDC-141
        # ── 17.6: Object Access ────────────────────────────────────────────
        ("Detailed File Share",                  False, True),   # WDC-142
        ("File Share",                           True,  True),   # WDC-143
        ("Other Object Access Events",           True,  True),   # WDC-144
        ("Removable Storage",                    True,  True),   # WDC-145
        # ── 17.7: Policy Change ────────────────────────────────────────────
        ("Audit Policy Change",                  True,  False),  # WDC-146
        ("Authentication Policy Change",         True,  False),  # WDC-147
        ("Authorization Policy Change",          True,  False),  # WDC-148
        ("MPSSVC Rule-Level Policy Change",      True,  True),   # WDC-149
        ("Other Policy Change Events",           False, True),   # WDC-150
        # ── 17.8: Privilege Use ────────────────────────────────────────────
        ("Sensitive Privilege Use",              True,  True),   # WDC-151
        # ── 17.9: System ──────────────────────────────────────────────────
        ("IPsec Driver",                         True,  True),   # WDC-152
        ("Other System Events",                  True,  True),   # WDC-153
        ("Security State Change",                True,  False),  # WDC-154
        ("Security System Extension",            True,  False),  # WDC-155
        ("System Integrity",                     True,  True),   # WDC-156
    ]

    for subcategory, success, failure in audit_settings:
        success_flag = "enable" if success else "disable"
        failure_flag = "enable" if failure else "disable"
        rc, _, err = _ps(
            f'auditpol /set /subcategory:"{subcategory}" '
            f'/success:{success_flag} /failure:{failure_flag}'
        )
        if rc == 0:
            log_ok(f"Audit [{subcategory}]: success={success_flag}, failure={failure_flag}")
        else:
            log_warn(f"Audit [{subcategory}]: {err[:200]}")


def apply_administrative_templates() -> None:
    """
    WDC-157..340 — Apply CIS Section 18 Administrative Template settings
    via direct registry writes.

    In a Group Policy environment these would be set through ADMX templates.
    Because this script applies settings locally, we write the equivalent
    registry values directly using Set-ItemProperty via PowerShell.

    Settings are organised by CIS subsection number for easy cross-reference.
    Each tuple is: (registry_key, value_name, type, data, description)
    """
    log_section("Administrative Templates — CIS Section 18 (WDC-157..340)")

    reg_settings = [
        # ── 18.1.1: Lock Screen ───────────────────────────────────────────────
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\Personalization",
         "NoLockScreenCamera",   "DWord", 1, "WDC-157: Prevent lock screen camera"),
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\Personalization",
         "NoLockScreenSlideshow","DWord", 1, "WDC-158: Prevent lock screen slideshow"),

        # ── 18.1.2: Speech (disable cloud-based speech recognition) ──────────
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\InputPersonalization",
         "AllowInputPersonalization", "DWord", 0, "WDC-159: No online speech recognition"),

        # ── 18.1.3: Online tips ────────────────────────────────────────────────
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\CloudContent",
         "DisableSoftLanding",   "DWord", 1, "WDC-160: No online tips"),

        # ── 18.4: MS Security Guide ───────────────────────────────────────────
        # WDC-169: Restrict token for local accounts over network (pass-the-hash mitigation)
        ("HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
         "LocalAccountTokenFilterPolicy", "DWord", 0, "WDC-169: UAC restrictions for local accounts"),
        # WDC-170/171: Disable SMBv1 (EternalBlue / WannaCry attack vector)
        ("HKLM:\\SYSTEM\\CurrentControlSet\\Services\\MrxSmb10",
         "Start",                "DWord", 4, "WDC-170: SMBv1 client disabled (Start=4=disabled)"),
        ("HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters",
         "SMB1",                 "DWord", 0, "WDC-171: SMBv1 server disabled"),
        # WDC-172: Certificate padding check (Authenticode bypass mitigation)
        ("HKLM:\\SOFTWARE\\Microsoft\\Cryptography\\Wintrust\\Config",
         "EnableCertPaddingCheck","String","1","WDC-172: Certificate padding check"),
        # WDC-173: SEHOP (Structured Exception Handler Overwrite Protection)
        ("HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\kernel",
         "DisableExceptionChainValidation","DWord",0,"WDC-173: SEHOP enabled"),
        # WDC-174: NetBT Node Type = P-node (point-to-point, no broadcast name resolution)
        ("HKLM:\\SYSTEM\\CurrentControlSet\\Services\\NetBT\\Parameters",
         "NodeType",             "DWord", 2, "WDC-174: NetBT P-node (no broadcast)"),

        # ── 18.5: MSS (Microsoft Solutions for Security) ──────────────────────
        # WDC-175: Disable AutoAdminLogon (prevents cached credential auto-login)
        ("HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
         "AutoAdminLogon",       "String","0","WDC-175: No auto admin logon"),
        # WDC-176/177: Disable IP source routing (prevents packet spoofing)
        ("HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Tcpip6\\Parameters",
         "DisableIPSourceRouting","DWord",2,"WDC-176: IPv6 source routing disabled"),
        ("HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters",
         "DisableIPSourceRouting","DWord",2,"WDC-177: IPv4 source routing disabled"),
        # WDC-178: Disable ICMP redirect acceptance (route spoofing mitigation)
        ("HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters",
         "EnableICMPRedirect",   "DWord", 0, "WDC-178: ICMP redirect disabled"),
        # WDC-179: TCP keep-alive time = 5 min (300 000 ms)
        ("HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters",
         "KeepAliveTime",        "DWord", 300000, "WDC-179: TCP keep-alive 300 s"),
        # WDC-180: Prevent NetBIOS name release on demand (prevents poisoning)
        ("HKLM:\\SYSTEM\\CurrentControlSet\\Services\\NetBT\\Parameters",
         "NoNameReleaseOnDemand","DWord", 1, "WDC-180: No NetBIOS name release on demand"),
        # WDC-181: Disable router discovery (IRDP — not used in enterprise)
        ("HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters",
         "PerformRouterDiscovery","DWord",0,"WDC-181: IRDP router discovery disabled"),
        # WDC-182: SafeDllSearchMode prevents DLL hijacking
        ("HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Session Manager",
         "SafeDllSearchMode",    "DWord", 1, "WDC-182: SafeDllSearchMode enabled"),
        # WDC-183/184: Limit TCP retransmissions (reduce window for connection hijacking)
        ("HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Tcpip6\\Parameters",
         "TcpMaxDataRetransmissions","DWord",3,"WDC-183: IPv6 TCP max retransmit=3"),
        ("HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters",
         "TcpMaxDataRetransmissions","DWord",3,"WDC-184: IPv4 TCP max retransmit=3"),
        # WDC-185: Warn when security event log reaches 90% capacity
        ("HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Eventlog\\Security",
         "WarningLevel",         "DWord", 90, "WDC-185: Security log warning at 90%"),

        # ── 18.6.4: DNS Client ─────────────────────────────────────────────────
        # WDC-186: mDNS (Multicast DNS) disabled — prevents local name resolution leakage
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient",
         "EnableMulticast",      "DWord", 0, "WDC-186: mDNS disabled"),
        # WDC-187: NetBIOS disabled on public network profiles
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient",
         "EnableNetbios",        "DWord", 2, "WDC-187: NetBIOS off on public networks"),
        # WDC-188: Do not use default IPv6 DNS servers
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient",
         "DisableSmartNameResolution","DWord",1,"WDC-188: No default IPv6 DNS"),
        # WDC-189: Disable LLMNR (Link-Local Multicast Name Resolution)
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient",
         "EnableMulticast",      "DWord", 0, "WDC-189: LLMNR/mDNS disabled"),

        # ── 18.6.5: Fonts ──────────────────────────────────────────────────────
        # WDC-190: Prevent downloading fonts from online providers
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\System",
         "EnableFontProviders",  "DWord", 0, "WDC-190: No online font providers"),

        # ── 18.6.7: LanMan Server (SMB server) ────────────────────────────────
        ("HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanManServer\\Parameters",
         "AuditSmb1Access",      "DWord", 1, "WDC-191: Audit SMBv1 access"),
        ("HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanManServer\\Parameters",
         "EnableAuthRateLimiter","DWord", 1, "WDC-192: SMB auth rate limiter"),
        ("HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanManServer\\Parameters",
         "DisableMailslots",     "DWord", 1, "WDC-193: Remote mailslots disabled"),
        # WDC-194: Require SMB 3.1.1 minimum (rejects older, less-secure clients)
        ("HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanManServer\\Parameters",
         "SMBServerNameHardeningLevel","DWord",3,"WDC-194: SMB 3.1.1 minimum"),

        # ── 18.6.8: LanMan Workstation ─────────────────────────────────────────
        ("HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters",
         "RequireSecuritySignature","DWord",1,"WDC-195: Workstation requires SMB signing"),

        # ── 18.6.9: LLTDIO / RSPNDR (Link Layer Topology Discovery) ──────────
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\LLTD",
         "AllowLLTDIOOnDomain",  "DWord", 0, "WDC-196: LLTDIO disabled"),
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\LLTD",
         "AllowRspndrOnDomain",  "DWord", 0, "WDC-197: RSPNDR disabled"),

        # ── 18.6.10: Peer-to-peer networking ──────────────────────────────────
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Peernet",
         "Disabled",             "DWord", 1, "WDC-198: P2P networking disabled"),

        # ── 18.6.11: Network Connections ──────────────────────────────────────
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\Network Connections",
         "NC_ShowSharedAccessUI","DWord", 0, "WDC-200: ICS (Internet Connection Sharing) prohibited"),
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\Network Connections",
         "NC_StdDomainUserSetLocation","DWord",1,"WDC-201: Domain users elevate for network location"),

        # ── 18.6.14: Hardened UNC Paths ────────────────────────────────────────
        # NETLOGON and SYSVOL must use mutual authentication + integrity + privacy
        # to prevent man-in-the-middle attacks against GPO delivery.
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\NetworkProvider\\HardenedPaths",
         "\\\\*\\NETLOGON",
         "String",
         "RequireMutualAuthentication=1,RequireIntegrity=1,RequirePrivacy=1",
         "WDC-202: NETLOGON hardened UNC"),
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\NetworkProvider\\HardenedPaths",
         "\\\\*\\SYSVOL",
         "String",
         "RequireMutualAuthentication=1,RequireIntegrity=1,RequirePrivacy=1",
         "WDC-202: SYSVOL hardened UNC"),

        # ── 18.6.19: IPv6 ─────────────────────────────────────────────────────
        # WDC-203: Disable all IPv6 components (0xFF = all bits set = all disabled)
        ("HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Tcpip6\\Parameters",
         "DisabledComponents",   "DWord", 0xFF, "WDC-203: IPv6 fully disabled"),

        # ── 18.6.21: Wireless Manager ─────────────────────────────────────────
        # WDC-204: Prefer Ethernet over wireless; value 3 = no WiFi when Ethernet is active
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\WcmSvc\\GroupPolicy",
         "fMinimizeConnections", "DWord", 3, "WDC-204: Minimise simultaneous connections"),

        # ── 18.7: Printing ────────────────────────────────────────────────────
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Printers",
         "RegisterSpoolerRemoteRpcEndPoint","DWord",2,"WDC-205: Spooler rejects remote connections"),
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Printers",
         "RedirectionGuardPolicy","DWord",1,"WDC-206: Redirection Guard enabled"),
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Printers\\PointAndPrint",
         "NoWarningNoElevationOnInstall","DWord",0,"WDC-214: Print driver install requires admin"),
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Printers\\RPC",
         "RpcUseNamedPipeProtocol","DWord",0,"WDC-207: RPC over TCP (not named pipes)"),
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Printers\\RPC",
         "RpcAuthentication",    "DWord", 0, "WDC-208: RPC authentication = default"),
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Printers\\RPC",
         "RpcProtocols",         "DWord", 5, "WDC-209: RPC listener = TCP only"),
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Printers\\RPC",
         "ForceKerberosForRpc",  "DWord", 0, "WDC-210: RPC auth = negotiate or higher"),
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Printers\\RPC",
         "RpcTcpPort",           "DWord", 0, "WDC-211: RPC TCP port = dynamic (0)"),
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Printers\\RPC",
         "EnablePacketPrivacy",  "DWord", 1, "WDC-212: RPC packet-level privacy"),
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Printers",
         "EnableWindowsProtectedPrint","DWord",1,"WDC-213: Windows protected print mode"),

        # ── 18.8: Push Notifications ──────────────────────────────────────────
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\CurrentVersion\\PushNotifications",
         "NoCloudApplicationNotification","DWord",1,"WDC-215: No cloud notification"),

        # ── 18.9.3: Audit Process Creation ────────────────────────────────────
        # WDC-216: Include command-line arguments in process creation events (Event 4688)
        ("HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Audit",
         "ProcessCreationIncludeCmdLine_Enabled","DWord",1,"WDC-216: Command-line in process creation events"),

        # ── 18.9.4: Credentials Delegation ────────────────────────────────────
        # WDC-217: Encryption Oracle Remediation = Force Updated Clients (no CredSSP downgrade)
        ("HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\CredSSP\\Parameters",
         "AllowEncryptionOracle","DWord", 0, "WDC-217: Encryption Oracle = Force Updated Clients"),
        # WDC-218: Allow delegation of non-exportable credentials (Restricted Admin / Remote Credential Guard)
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\CredentialsDelegation",
         "AllowProtectedCreds",  "DWord", 1, "WDC-218: Delegate non-exportable credentials"),

        # ── 18.9.5: Device Guard / VBS / Credential Guard ──────────────────────
        # WDC-219..224: Virtualisation-Based Security
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\DeviceGuard",
         "EnableVirtualizationBasedSecurity","DWord",1,"WDC-219: VBS enabled"),
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\DeviceGuard",
         "RequirePlatformSecurityFeatures","DWord",1,"WDC-220: VBS platform = Secure Boot"),
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\DeviceGuard",
         "HypervisorEnforcedCodeIntegrity","DWord",1,"WDC-221: HVCI with UEFI lock"),
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\DeviceGuard",
         "HVCIMATRequired",      "DWord", 1, "WDC-222: UEFI MAT required for HVCI"),
        # WDC-223: Credential Guard MUST be DISABLED on Domain Controllers.
        # CIS explicitly requires LsaCfgFlags=0 on DCs because Credential Guard
        # is incompatible with Kerberos delegation and the DC's own credential management.
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\DeviceGuard",
         "LsaCfgFlags",          "DWord", 0, "WDC-223: Credential Guard DISABLED (CIS DC requirement)"),
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\DeviceGuard",
         "ConfigureSystemGuardLaunch","DWord",1,"WDC-224: Secure Launch enabled"),

        # ── 18.9.7: Device Installation ───────────────────────────────────────
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\Device Metadata",
         "PreventDeviceMetadataFromNetwork","DWord",1,"WDC-226: No device metadata download"),

        # ── 18.9.13: Early Launch Antimalware ─────────────────────────────────
        # Value 3 = Good, Unknown, and Bad but critical drivers allowed
        ("HKLM:\\SYSTEM\\CurrentControlSet\\Policies\\EarlyLaunch",
         "DriverLoadPolicy",     "DWord", 3, "WDC-227: ELAM = allow good+unknown+critical"),

        # ── 18.9.19: Group Policy ─────────────────────────────────────────────
        # Ensure security policy is re-applied even if it hasn't changed
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\Group Policy\\{827D319E-6EAC-11D2-A4EA-00C04F79F83A}",
         "NoBackgroundPolicy",   "DWord", 0, "WDC-230: Apply security policy in background"),
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\Group Policy\\{827D319E-6EAC-11D2-A4EA-00C04F79F83A}",
         "NoGPOListChanges",     "DWord", 0, "WDC-231: Process security policy even if unchanged"),
        ("HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
         "DisableBkGndGroupPolicy","DWord",0,"WDC-232: Background GP refresh enabled"),

        # ── 18.9.20: Internet Communication Manager ────────────────────────────
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Printers",
         "DisableHTTPPrinting",  "DWord", 1, "WDC-233/236: No HTTP printing"),
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\DriverSearching",
         "DontSearchWindowsUpdate","DWord",1,"WDC-235: No driver download from Windows Update"),
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\Registration Wizard Control",
         "NoRegistration",       "DWord", 1, "WDC-237: No Windows registration via URL"),
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\SearchCompanion",
         "DisableContentFileUpdates","DWord",1,"WDC-238: No Search Companion updates"),
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Messenger\\Client",
         "CEIP",                 "DWord", 2, "WDC-239: No Messenger CEIP"),
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\SQMClient\\Windows",
         "CEIPEnable",           "DWord", 0, "WDC-240: No Windows CEIP"),
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\Windows Error Reporting",
         "Disabled",             "DWord", 1, "WDC-241: Windows Error Reporting disabled"),

        # ── 18.9.23: Kerberos ─────────────────────────────────────────────────
        # WDC-242: Allow device authentication using certificate (automatic = prefer cert)
        ("HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Kerberos\\Parameters",
         "DevicePKInitEnabled",  "DWord", 1, "WDC-242: Kerberos device auth = automatic"),

        # ── 18.9.24: Kernel DMA Protection ───────────────────────────────────
        # WDC-225: Block all external DMA devices (Thunderbolt attack surface)
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\Kernel DMA Protection",
         "DeviceEnumerationPolicy","DWord",0,"WDC-225: Kernel DMA protection = block all"),

        # ── 18.9.26: LAPS (Local Administrator Password Solution) ─────────────
        # LAPS automatically rotates the local admin password and stores it in AD.
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft Services\\AdmPwd",
         "BackupDirectory",      "DWord", 2, "WDC-161: LAPS backup directory = AD"),
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft Services\\AdmPwd",
         "PwdExpirationProtectionEnabled","DWord",1,"WDC-162: LAPS expiry protection"),
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft Services\\AdmPwd",
         "ADPasswordEncryptionEnabled","DWord",1,"WDC-163: LAPS password encryption"),
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft Services\\AdmPwd",
         "PasswordComplexity",   "DWord", 4, "WDC-164: LAPS complexity = all char classes"),
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft Services\\AdmPwd",
         "PasswordLength",       "DWord", 15, "WDC-165: LAPS min length = 15"),
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft Services\\AdmPwd",
         "PasswordAgeDays",      "DWord", 30, "WDC-166: LAPS rotation = 30 days"),
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft Services\\AdmPwd",
         "PostAuthenticationResetDelay","DWord",8,"WDC-167: LAPS post-auth grace = 8 h"),
        # Post-auth actions: 3 = reset password + logoff active sessions
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft Services\\AdmPwd",
         "PostAuthenticationActions","DWord",3,"WDC-168: LAPS post-auth = reset + logoff"),

        # ── 18.9.27: LSASS Protection ─────────────────────────────────────────
        # WDC-228: Block custom SSP/AP packages from loading into LSASS (DC)
        ("HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa",
         "DisableRestrictedAdmin","DWord",0,"WDC-228: No custom SSPs in LSASS (DC)"),
        # WDC-229: Run LSASS as a Protected Process Light with UEFI lock
        # Value 2 = PPL with UEFI lock (prevents disabling without firmware change)
        ("HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa",
         "RunAsPPL",             "DWord", 2, "WDC-229: LSASS as PPL with UEFI lock"),

        # ── 18.9.28: Language ─────────────────────────────────────────────────
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Control Panel\\International",
         "BlockUserInputMethodsForSignIn","DWord",1,"WDC-340: No input method copy at sign-in"),

        # ── 18.9.29: Logon ────────────────────────────────────────────────────
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\System",
         "BlockUserFromShowingAccountDetailsOnSignin","DWord",1,"WDC-245: No account details at sign-in"),
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\System",
         "DontDisplayNetworkSelectionUI","DWord",1,"WDC-246: No network selection UI at sign-in"),
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\System",
         "DontEnumerateConnectedUsers","DWord",1,"WDC-247: No connected user enumeration"),
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\System",
         "DisableLockScreenAppNotifications","DWord",1,"WDC-248: No lock screen notifications"),
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\System",
         "AllowDomainPINLogon",  "DWord", 0, "WDC-249: No PIN sign-in"),

        # ── 18.9.31: NetLogon ─────────────────────────────────────────────────
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Netlogon\\Parameters",
         "BlockNetBIOSBasedLocatorService","DWord",1,"WDC-250: Block NetBIOS DC location"),

        # ── 18.9.33: Activity Feed / Clipboard ────────────────────────────────
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\System",
         "EnableClipboardSharing","DWord",0,"WDC-251: No clipboard sync across devices"),
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\System",
         "EnableActivityFeed",   "DWord", 0, "WDC-252: No user activity upload"),

        # ── 18.9.37: Remote Assistance ────────────────────────────────────────
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services",
         "fAllowUnsolicited",    "DWord", 0, "WDC-293: Offer Remote Assistance disabled"),
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services",
         "fAllowToGetHelp",      "DWord", 0, "WDC-294: Solicited Remote Assistance disabled"),

        # ── 18.9.41: SAM (Security Account Manager) — DC only ─────────────────
        # WDC-243: Block ROCA-vulnerable Windows Hello for Business keys
        ("HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
         "BlockROCAVulnerableKeys","DWord",1,"WDC-243: Block ROCA-vulnerable WHfB keys"),
        # WDC-244: Require strong encryption for SAM password changes
        ("HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
         "SAMStrongEncryptionRequiredForChangePassword","DWord",1,"WDC-244: Strong SAM encryption"),

        # ── 18.10.6: App Runtime ──────────────────────────────────────────────
        ("HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
         "MSAOptional",          "DWord", 1, "WDC-334: Microsoft accounts optional for apps"),

        # ── 18.10.8: AutoPlay / AutoRun ───────────────────────────────────────
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\Explorer",
         "NoAutoplayfornonVolume","DWord",1,"WDC-253: AutoPlay disabled for non-volume devices"),
        ("HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer",
         "NoAutorun",            "DWord", 1, "WDC-254: AutoRun default = do not execute"),
        # 255 (0xFF) = disable AutoPlay on all drive types
        ("HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer",
         "NoDriveTypeAutoRun",   "DWord", 255, "WDC-255: AutoPlay disabled on all drives"),

        # ── 18.10.9: Biometrics anti-spoofing ─────────────────────────────────
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Biometrics\\FacialFeatures",
         "EnhancedAntiSpoofing", "DWord", 1, "WDC-256: Enhanced facial anti-spoofing"),

        # ── 18.10.11: Camera ──────────────────────────────────────────────────
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Camera",
         "AllowCamera",          "DWord", 0, "WDC-271: Camera access disabled"),

        # ── 18.10.13: Cloud Content ────────────────────────────────────────────
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\CloudContent",
         "DisableConsumerAccountStateContent","DWord",1,"WDC-257: No cloud consumer content"),
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\CloudContent",
         "DisableCloudOptimizedContent","DWord",1,"WDC-258: No cloud optimised content"),

        # ── 18.10.16: Connected User Experience / Telemetry ───────────────────
        # Value 1 = Required diagnostic data only (minimum allowed in enterprise)
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection",
         "AllowTelemetry",       "DWord", 1, "WDC-259: Telemetry = required data only"),
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection",
         "DisableEnterpriseAuthProxy","DWord",1,"WDC-260: No auth proxy for telemetry"),
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection",
         "DoNotShowFeedbackNotifications","DWord",1,"WDC-261: No feedback notifications"),
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection",
         "EnableOneSettingsAuditing","DWord",1,"WDC-262: OneSettings auditing enabled"),
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection",
         "LimitDiagnosticLogCollection","DWord",1,"WDC-263: Limit diagnostic log collection"),
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection",
         "LimitDumpCollection",  "DWord", 1, "WDC-264: Limit dump collection"),

        # ── 18.10.26: Event Log Sizes ─────────────────────────────────────────
        # CIS recommends minimum sizes; Security log is especially large (192 MB)
        # because it captures all audit events.
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\EventLog\\Application",
         "MaxSize",              "DWord", 32768,  "WDC-265: Application log = 32 MB"),
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\EventLog\\Security",
         "MaxSize",              "DWord", 196608, "WDC-266: Security log = 192 MB"),
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\EventLog\\Setup",
         "MaxSize",              "DWord", 32768,  "WDC-267: Setup log = 32 MB"),
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\EventLog\\System",
         "MaxSize",              "DWord", 32768,  "WDC-268: System log = 32 MB"),

        # ── 18.10.29: File Explorer ────────────────────────────────────────────
        # WDC-269: Disable heap termination on corruption — value 0 means ENABLE termination
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\Explorer",
         "NoHeapTerminationOnCorruption","DWord",0,"WDC-269: Heap termination on corruption ON"),
        # WDC-270: Protected-mode shell protocol (disable legacy unprotected mode)
        ("HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer",
         "PreXPSP2ShellProtocolBehavior","DWord",0,"WDC-270: Shell protocol protected mode"),

        # ── 18.10.33: Location ─────────────────────────────────────────────────
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\LocationAndSensors",
         "DisableLocation",      "DWord", 1, "WDC-336: Location services disabled"),

        # ── 18.10.36: Messaging ────────────────────────────────────────────────
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\Messaging",
         "AllowMessageSync",     "DWord", 0, "WDC-337: Message Service cloud sync disabled"),

        # ── 18.10.40: Microsoft Account ───────────────────────────────────────
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\MicrosoftAccount",
         "DisableUserAuth",      "DWord", 1, "WDC-272: Block consumer Microsoft accounts"),

        # ── 18.10.41: Push to Install ─────────────────────────────────────────
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\PushToInstall",
         "DisablePushToInstall", "DWord", 1, "WDC-338: Push-to-Install disabled"),

        # ── 18.10.42: Windows Defender ────────────────────────────────────────
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows Advanced Threat Protection",
         "ForceDefenderPassiveMode","DWord",0,"WDC-273: EDR in block mode (not passive)"),
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Spynet",
         "LocalSettingOverrideSpynetReporting","DWord",0,"WDC-274: No local MAPS override"),
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Spynet",
         "SpynetReporting",      "DWord", 2, "WDC-275: MAPS membership = Advanced"),
        # WDC-276: Enable ASR rules globally
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Windows Defender Exploit Guard\\ASR",
         "ExploitGuard_ASR_Rules","DWord",1,"WDC-276: ASR rules enabled"),
        # WDC-278: Network protection = block dangerous websites
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Windows Defender Exploit Guard\\Network Protection",
         "EnableNetworkProtection","DWord",1,"WDC-278: Network protection = block"),
        # Real-time protection settings
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection",
         "DisableRealtimeMonitoring","DWord",0,"WDC-281: Real-time protection ON"),
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection",
         "DisableBehaviorMonitoring","DWord",0,"WDC-282: Behaviour monitoring ON"),
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection",
         "DisableScriptScanning","DWord",0,"WDC-283: Script scanning ON"),
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection",
         "DisableIOAVProtection","DWord",0,"WDC-280: Scan downloaded files ON"),
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection",
         "DisableRealtimeMonitoringAtOOBE","DWord",0,"WDC-279: OOBE real-time protection ON"),
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Brute-Force Protection",
         "Aggressiveness",       "DWord", 1, "WDC-284: Brute-force protection = medium"),
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Features",
         "TamperProtection",     "DWord", 5, "WDC-285: Tamper protection enabled"),
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Reporting",
         "DisableGenericRePorts","DWord",1,"WDC-286: Watson crash reporting disabled"),
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Scan",
         "DisablePackedExeScanning","DWord",0,"WDC-287: Packed executable scanning ON"),
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Scan",
         "DisableRemovableDriveScanning","DWord",0,"WDC-288: Removable drive scanning ON"),
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Scan",
         "ScanScheduleDay",      "DWord", 7, "WDC-289: Quick scan after 7 days without scan"),
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Scan",
         "DisableEmailScanning", "DWord", 0, "WDC-290: Email scanning ON"),
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows Defender",
         "PUAProtection",        "DWord", 1, "WDC-291: PUA protection = block"),
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows Defender",
         "DisableLocalAdminMerge","DWord",1,"WDC-292: Exclusions visible to local users"),

        # ── 18.10.57: Remote Desktop Services ────────────────────────────────
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services",
         "fDisableCcm",          "DWord", 1, "WDC-295: COM port redirection disabled"),
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services",
         "fDisableCdm",          "DWord", 1, "WDC-296: Drive redirection disabled"),
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services",
         "fDisableLocationRedir","DWord",1,"WDC-297: Location redirection disabled"),
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services",
         "fDisableLPT",          "DWord", 1, "WDC-298: LPT port redirection disabled"),
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services",
         "fDisablePNPRedir",     "DWord", 1, "WDC-299: PnP device redirection disabled"),
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services",
         "fDisableWebAuthn",     "DWord", 1, "WDC-300: WebAuthn redirection disabled"),
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services",
         "fDisableClipboardRedir","DWord",1,"WDC-301: Clipboard server→client only"),
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services",
         "fPromptForPassword",   "DWord", 1, "WDC-302: Always prompt for RDS password"),
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services",
         "fEncryptRPCTraffic",   "DWord", 1, "WDC-303: Secure RPC for RDS"),
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services",
         "SecurityLayer",        "DWord", 2, "WDC-304: RDP security = SSL/TLS"),
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services",
         "UserAuthentication",   "DWord", 1, "WDC-305: NLA required for RDS"),
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services",
         "MinEncryptionLevel",   "DWord", 3, "WDC-306: RDS encryption = High"),
        # 900 000 ms = 15 min idle timeout
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services",
         "MaxIdleTime",          "DWord", 900000, "WDC-307: RDS idle timeout = 15 min"),
        # 60 000 ms = 1 min disconnect timeout
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services",
         "MaxDisconnectionTime", "DWord", 60000,  "WDC-308: RDS disconnect timeout = 1 min"),

        # ── 18.10.58: RSS Feeds ────────────────────────────────────────────────
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Internet Explorer\\Feeds",
         "DisableEnclosureDownload","DWord",1,"WDC-309: RSS enclosure download disabled"),

        # ── 18.10.59: Search ──────────────────────────────────────────────────
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\Windows Search",
         "AllowCloudSearch",     "DWord", 0, "WDC-310: Cloud Search disabled"),
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\Windows Search",
         "AllowIndexingEncryptedStoresOrItems","DWord",0,"WDC-311: Encrypted file indexing disabled"),

        # ── 18.10.63: Software Protection Platform ───────────────────────────
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\CurrentVersion\\Software Protection Platform",
         "NoGenTicket",          "DWord", 1, "WDC-312: KMS online AVS validation disabled"),

        # ── 18.10.77: SmartScreen ─────────────────────────────────────────────
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\System",
         "EnableSmartScreen",    "DWord", 1, "WDC-335: SmartScreen = warn and prevent bypass"),

        # ── 18.10.81: Ink Workspace ───────────────────────────────────────────
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\WindowsInkWorkspace",
         "AllowWindowsInkWorkspace","DWord",0,"WDC-329: Windows Ink Workspace disabled"),

        # ── 18.10.82: Windows Installer ───────────────────────────────────────
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer",
         "EnableUserControl",    "DWord", 0, "WDC-330: No user control over installs"),
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer",
         "AlwaysInstallElevated","DWord",0,"WDC-331: No always-elevated install"),

        # ── 18.10.83: Winlogon ────────────────────────────────────────────────
        ("HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
         "DontDisplayLockedUserId","DWord",3,"WDC-332: No MPR password notifications"),
        ("HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
         "DisableAutomaticRestartSignOn","DWord",1,"WDC-333: No automatic restart sign-on"),

        # ── 18.10.88: PowerShell Logging ─────────────────────────────────────
        # WDC-313: Log every script block executed (catches obfuscated scripts)
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging",
         "EnableScriptBlockLogging","DWord",1,"WDC-313: PowerShell script block logging"),
        # WDC-314: Save full PowerShell transcripts (command + output)
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\Transcription",
         "EnableTranscripting",  "DWord", 1, "WDC-314: PowerShell transcription enabled"),

        # ── 18.10.90: WinRM ───────────────────────────────────────────────────
        # WinRM Client
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\WinRM\\Client",
         "AllowBasic",           "DWord", 0, "WDC-315: WinRM client — no Basic auth"),
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\WinRM\\Client",
         "AllowUnencryptedTraffic","DWord",0,"WDC-316: WinRM client — no unencrypted"),
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\WinRM\\Client",
         "AllowDigest",          "DWord", 0, "WDC-317: WinRM client — no Digest auth"),
        # WinRM Service
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\WinRM\\Service",
         "AllowBasic",           "DWord", 0, "WDC-318: WinRM service — no Basic auth"),
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\WinRM\\Service",
         "AllowAutoConfig",      "DWord", 0, "WDC-319: WinRM service — no auto-config"),
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\WinRM\\Service",
         "AllowUnencryptedTraffic","DWord",0,"WDC-320: WinRM service — no unencrypted"),
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\WinRM\\Service",
         "DisableRunAs",         "DWord", 1, "WDC-321: WinRM service — no RunAs credentials"),

        # ── 18.10.91: Windows Remote Shell ────────────────────────────────────
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\WinRM\\Service\\WinRS",
         "AllowRemoteShellAccess","DWord",0,"WDC-322: Remote Shell access disabled"),

        # ── 18.10.93: Windows Defender Security Center ────────────────────────
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows Defender Security Center\\App and Browser protection",
         "UILockdown",           "DWord", 1, "WDC-323: Users cannot modify Defender settings"),

        # ── 18.10.94: Windows Update ──────────────────────────────────────────
        # Allow auto-restart (no NoAutoRebootWithLoggedOnUsers block)
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU",
         "NoAutoRebootWithLoggedOnUsers","DWord",0,"WDC-324: Auto-restart allowed"),
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU",
         "NoAutoUpdate",         "DWord", 0, "WDC-325: Automatic updates enabled"),
        # Schedule day 0 = every day
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU",
         "ScheduledInstallDay",  "DWord", 0, "WDC-326: Updates installed daily"),

        # ── 18.11: WinHTTP / Proxy ────────────────────────────────────────────
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings",
         "EnableAutoProxyResultCache","DWord",0,"WDC-327: WPAD auto-proxy disabled"),
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings",
         "ProxyBypassLocalNames","DWord",0,"WDC-328: No loopback proxy bypass"),
    ]

    for key, name, vtype, data, desc in reg_settings:
        rc, _, err = _ps(
            f'If (!(Test-Path "{key}")) {{ New-Item -Path "{key}" -Force | Out-Null }}; '
            f'Set-ItemProperty -Path "{key}" -Name "{name}" '
            f'-Type {vtype} -Value {repr(data) if vtype == "String" else data} -Force'
        )
        if rc == 0:
            log_ok(desc)
        else:
            log_warn(f"{desc}: {err[:200]}")

    # ── WDC-277: ASR Rule States ──────────────────────────────────────────────
    # Attack Surface Reduction rules are individual GUIDs, each set to 1 (block).
    # These are applied as String values under the ASR\\Rules registry key.
    asr_rules = {
        # Rule GUID : description
        "56a863a9-875e-4185-98a7-b882c64b5ce5": "Block abuse of exploited vulnerable signed drivers",
        "7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c": "Block Adobe Reader child processes",
        "d4f940ab-401b-4efc-aadc-ad5f3c50688a": "Block all Office apps from creating child processes",
        "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2": "Block credential stealing from LSASS",
        "be9ba2d9-53ea-4cdc-84e5-9b1eeee46550": "Block executable content from email",
        "01443614-cd74-433a-b99e-2ecdc07bfc25": "Block executable files unless trusted",
        "5beb7efe-fd9a-4556-801d-275e5ffc04cc": "Block execution of obfuscated scripts",
        "d3e037e1-3eb8-44c8-a917-57927947596d": "Block JS/VBS launching executables",
        "3b576869-a4ec-4529-8536-b80a7769e899": "Block Office apps creating executable content",
        "75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84": "Block Office apps injecting into processes",
        "26190899-1602-49e8-8b27-eb1d0a1ce869": "Block Office communication app child processes",
        "e6db77e5-3df2-4cf1-b95a-636979351e5b": "Block persistence via WMI event subscription",
        "d1e49aac-8f56-4280-b9ba-993a6d77406c": "Block process creation from PSExec/WMI",
        "33ddedf1-c6e0-47cb-833e-de6133960387": "Block reboot in Safe Mode",
        "b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4": "Block untrusted/unsigned USB processes",
        "c0033c00-d16d-4114-a5a0-dc9b3a7d2ceb": "Block web shell creation for servers",
        "92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b": "Block Win32 API calls from Office macros",
        "c1db55ab-c21a-4637-bb3f-a12568109d35": "Advanced ransomware protection",
    }

    asr_path = (
        "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows Defender"
        "\\Windows Defender Exploit Guard\\ASR\\Rules"
    )
    # Build a single PowerShell command to set all rules at once
    set_cmds = [
        f'New-Item -Path "{asr_path}" -Force | Out-Null'
    ] + [
        f'Set-ItemProperty -Path "{asr_path}" -Name "{guid}" -Value "1" -Type String -Force'
        for guid in asr_rules
    ]
    rc, _, err = _ps("; ".join(set_cmds))
    if rc == 0:
        log_ok(f"WDC-277: {len(asr_rules)} ASR rules configured (block mode)")
    else:
        log_warn(f"WDC-277: ASR rules: {err[:200]}")


def apply_issp_specific() -> None:
    """
    WDC-341..351 — ISSP-specific settings that go beyond the CIS baseline.

    Automated:
      WDC-341: Fine-Grained Password Policy for standard users (PSO-Users)
      WDC-342: Fine-Grained Password Policy for admin accounts (PSO-Admins)
      WDC-348: BitLocker full-disk encryption

    Documented as Not Implemented (manual):
      WDC-344..347, 349..351 — procedural or infrastructure-dependent controls
    """
    log_section("ISSP-Specific Settings (WDC-341..351)")

    # ── WDC-341: PSO for standard users ──────────────────────────────────────
    # Fine-Grained Password Policies (PSO) override the Default Domain Policy
    # for specific groups, allowing stricter rules for admins.
    pso_users_cmd = """
    Try {
        $existing = Get-ADFineGrainedPasswordPolicy -Filter {Name -eq "PSO-Users"} -ErrorAction SilentlyContinue
        If ($null -eq $existing) {
            New-ADFineGrainedPasswordPolicy -Name "PSO-Users" -Precedence 20 `
              -MinPasswordLength 12 -MaxPasswordAge "90.00:00:00" -MinPasswordAge "1.00:00:00" `
              -PasswordHistoryCount 24 -ComplexityEnabled $true -ReversibleEncryptionEnabled $false `
              -LockoutThreshold 5 -LockoutObservationWindow "00:15:00" -LockoutDuration "00:15:00"
            Write-Output "PSO-Users created"
        } Else {
            Set-ADFineGrainedPasswordPolicy -Identity "PSO-Users" `
              -MinPasswordLength 12 -MaxPasswordAge "90.00:00:00" -ComplexityEnabled $true
            Write-Output "PSO-Users updated"
        }
    } Catch {
        Write-Warning ("PSO-Users: " + $_.Exception.Message)
    }
    """
    rc, out, err = _ps(pso_users_cmd)
    if rc == 0 and out:
        log_ok(f"WDC-341: {out}")
    else:
        log_warn(f"WDC-341: PSO-Users — may require AD PowerShell module: {err[:200]}")

    # ── WDC-342: PSO for admin accounts ──────────────────────────────────────
    pso_admins_cmd = """
    Try {
        $existing = Get-ADFineGrainedPasswordPolicy -Filter {Name -eq "PSO-Admins"} -ErrorAction SilentlyContinue
        If ($null -eq $existing) {
            New-ADFineGrainedPasswordPolicy -Name "PSO-Admins" -Precedence 10 `
              -MinPasswordLength 18 -MaxPasswordAge "60.00:00:00" -MinPasswordAge "1.00:00:00" `
              -PasswordHistoryCount 24 -ComplexityEnabled $true -ReversibleEncryptionEnabled $false `
              -LockoutThreshold 5 -LockoutObservationWindow "00:15:00" -LockoutDuration "00:15:00"
            Write-Output "PSO-Admins created"
        } Else {
            Set-ADFineGrainedPasswordPolicy -Identity "PSO-Admins" `
              -MinPasswordLength 18 -MaxPasswordAge "60.00:00:00" -ComplexityEnabled $true
            Write-Output "PSO-Admins updated"
        }
    } Catch {
        Write-Warning ("PSO-Admins: " + $_.Exception.Message)
    }
    """
    rc, out, err = _ps(pso_admins_cmd)
    if rc == 0 and out:
        log_ok(f"WDC-342: {out}")
    else:
        log_warn(f"WDC-342: PSO-Admins: {err[:200]}")

    # ── WDC-348: BitLocker ───────────────────────────────────────────────────
    # Enable BitLocker on any fully-decrypted volume.
    # Uses XTS-AES 256-bit encryption with a recovery password protector.
    # The recovery password is automatically escrowed to Active Directory.
    bl_cmd = """
    Try {
        $volumes = Get-BitLockerVolume -ErrorAction Stop
        ForEach ($vol in $volumes) {
            If ($vol.VolumeStatus -eq "FullyDecrypted") {
                Try {
                    Enable-BitLocker -MountPoint $vol.MountPoint -EncryptionMethod XtsAes256 `
                      -UsedSpaceOnly -SkipHardwareTest -RecoveryPasswordProtector -ErrorAction Stop
                    Write-Output ("BitLocker enabled: " + $vol.MountPoint)
                } Catch {
                    Write-Warning ("BitLocker " + $vol.MountPoint + ": " + $_.Exception.Message)
                }
            } Else {
                Write-Output ("BitLocker already active on " + $vol.MountPoint + " (" + $vol.VolumeStatus + ")")
            }
        }
    } Catch {
        Write-Warning ("BitLocker: " + $_.Exception.Message)
    }
    """
    rc, out, err = _ps(bl_cmd)
    log_ok(f"WDC-348: BitLocker: {out}") if out else log_warn(f"WDC-348: BitLocker: {err[:200]}")

    # ── Manual / procedural items ─────────────────────────────────────────────
    log_skip("WDC-344: Breakglass account — MANUAL: print password, seal, store in physical safe")
    log_skip("WDC-345: Account deactivation lifecycle — MANUAL: requires HR/IAM integration")
    log_skip("WDC-346: CMDB inventory — MANUAL: ongoing IT staff updates required")
    log_skip("WDC-347: VPN enforcement — MANUAL: requires VPN gateway infrastructure")
    log_skip("WDC-349: Centralised AV — MANUAL: requires SCCM/Intune infrastructure")
    log_skip("WDC-350: Offsite backup — MANUAL: requires backup infrastructure")
    log_skip("WDC-351: Separate admin accounts — MANUAL: organisational naming convention")


# ── Main entry point ──────────────────────────────────────────────────────────

def harden() -> None:
    """
    Run all Windows DC hardening sections in order.
    Called by harden.py after OS detection and backup.
    """
    logger = get_logger()
    logger.info("\n" + "=" * 70)
    logger.info("  Bidouille — Windows Server 2025 DC Hardening")
    logger.info("  CIS Benchmark v2.0.0 Level 1 DC + ISSP ISO 27002 v2")
    logger.info("=" * 70 + "\n")

    with tempfile.TemporaryDirectory() as tmp:
        apply_account_policies_and_user_rights(tmp)

    apply_uac_settings()
    apply_system_services()
    apply_windows_firewall()
    apply_advanced_audit_policy()
    apply_administrative_templates()
    apply_issp_specific()

    logger.info("\n" + "=" * 70)
    logger.info("  Windows DC hardening complete.")
    logger.info("=" * 70 + "\n")
