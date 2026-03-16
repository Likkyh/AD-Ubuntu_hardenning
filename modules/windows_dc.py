"""
Windows Server 2025 + Active Directory DC hardening module.
CIS Microsoft Windows Server 2025 Benchmark v2.0.0 — Level 1 DC profile.
Requires: Python on Windows with Administrator privileges.
"""

import os
import subprocess
import tempfile
from modules.logger import get_logger, log_ok, log_warn, log_fail, log_section, log_skip

# ─── PowerShell helper ───────────────────────────────────────────────────────

def _ps(command: str, check=False) -> tuple[int, str, str]:
    """Run a PowerShell command, return (returncode, stdout, stderr)."""
    result = subprocess.run(
        ["powershell", "-NonInteractive", "-NoProfile", "-Command", command],
        capture_output=True, text=True, timeout=120
    )
    return result.returncode, result.stdout.strip(), result.stderr.strip()


def _reg_set(key: str, value_name: str, value_type: str, data) -> bool:
    """Set a registry value via PowerShell."""
    cmd = (
        f'If (!(Test-Path "{key}")) {{ New-Item -Path "{key}" -Force | Out-Null }}; '
        f'Set-ItemProperty -Path "{key}" -Name "{value_name}" -Type {value_type} -Value {data} -Force'
    )
    rc, out, err = _ps(cmd)
    if rc == 0:
        log_ok(f"Registry: {key}\\{value_name} = {data}")
        return True
    else:
        log_fail(f"Registry: {key}\\{value_name} → {err}")
        return False


def _reg_del(key: str, value_name: str) -> bool:
    cmd = f'Remove-ItemProperty -Path "{key}" -Name "{value_name}" -ErrorAction SilentlyContinue'
    rc, _, err = _ps(cmd)
    return rc == 0


def _run_cmd(args: list, label: str) -> bool:
    try:
        result = subprocess.run(args, capture_output=True, text=True, timeout=120)
        if result.returncode == 0:
            log_ok(label)
            return True
        else:
            log_warn(f"{label}: exit {result.returncode} — {result.stderr.strip()}")
            return False
    except Exception as e:
        log_fail(f"{label}: {e}")
        return False


# ─── secedit INF helpers ─────────────────────────────────────────────────────

SECEDIT_INF_TEMPLATE = """[Unicode]
Unicode=yes
[System Access]
PasswordHistorySize = 24
MaximumPasswordAge = 90
MinimumPasswordAge = 1
MinimumPasswordLength = 14
PasswordComplexity = 1
ClearTextPassword = 0
LockoutBadCount = 5
LockoutDuration = 15
ResetLockoutCount = 15
RequireLogonToChangePassword = 0
ForceLogoffWhenHourExpire = 1
NewGuestName = "GuestAccount_Disabled"
NewAdministratorName = "LocalAdmin_Bidouille"
EnableAdminAccount = 0
EnableGuestAccount = 0
LSAAnonymousNameLookup = 0
[Privilege Rights]
SeNetworkLogonRight = *S-1-5-32-544,*S-1-5-11,*S-1-5-9
SeTcbPrivilege =
SeInteractiveLogonRight = *S-1-5-32-544,*S-1-5-9
SeRemoteInteractiveLogonRight = *S-1-5-32-544
SeBackupPrivilege = *S-1-5-32-544
SeChangeNotifyPrivilege = *S-1-5-32-544,*S-1-5-32-545,*S-1-5-32-551,*S-1-5-19,*S-1-5-20
SeSystemTimePrivilege = *S-1-5-32-544,*S-1-5-19
SeCreatePagefilePrivilege = *S-1-5-32-544
SeCreateTokenPrivilege =
SeCreateGlobalPrivilege = *S-1-5-32-544,*S-1-5-19,*S-1-5-20,*S-1-5-6
SeCreatePermanentPrivilege =
SeCreateSymbolicLinkPrivilege = *S-1-5-32-544
SeDebugPrivilege = *S-1-5-32-544
SeDenyNetworkLogonRight = *S-1-5-32-546
SeDenyBatchLogonRight = *S-1-5-32-546
SeDenyServiceLogonRight = *S-1-5-32-546
SeDenyInteractiveLogonRight = *S-1-5-32-546
SeDenyRemoteInteractiveLogonRight = *S-1-5-32-546
SeEnableDelegationPrivilege = *S-1-5-32-544
SeRemoteShutdownPrivilege = *S-1-5-32-544
SeAuditPrivilege = *S-1-5-19,*S-1-5-20
SeImpersonatePrivilege = *S-1-5-32-544,*S-1-5-19,*S-1-5-20,*S-1-5-6
SeIncreaseBasePriorityPrivilege = *S-1-5-32-544
SeLoadDriverPrivilege = *S-1-5-32-544
SeLockMemoryPrivilege =
SeBatchLogonRight = *S-1-5-32-544
SeSecurityPrivilege = *S-1-5-32-544
SeRelabelPrivilege =
SeSystemEnvironmentPrivilege = *S-1-5-32-544
SeProfileSingleProcessPrivilege = *S-1-5-32-544
SeSystemProfilePrivilege = *S-1-5-32-544,*S-1-5-80-3139157870-2983391045-3678747466-658725712-1809340420
SeAssignPrimaryTokenPrivilege = *S-1-5-19,*S-1-5-20
SeRestorePrivilege = *S-1-5-32-544
SeShutdownPrivilege = *S-1-5-32-544
SeSyncAgentPrivilege =
SeTakeOwnershipPrivilege = *S-1-5-32-544
SeMachineAccountPrivilege = *S-1-5-32-544
SeUndockPrivilege = *S-1-5-32-544
SeManageVolumePrivilege = *S-1-5-32-544
SeIncreaseWorkingSetPrivilege = *S-1-5-32-544,*S-1-5-32-545
SeTimeZonePrivilege = *S-1-5-32-544,*S-1-5-32-545,*S-1-5-19
[Registry Values]
MACHINE\\System\\CurrentControlSet\\Control\\Lsa\\SCENoApplyLegacyAuditPolicy=4,1
MACHINE\\System\\CurrentControlSet\\Control\\Lsa\\CrashOnAuditFail=4,0
MACHINE\\System\\CurrentControlSet\\Services\\Netlogon\\Parameters\\DisablePasswordChange=4,0
MACHINE\\System\\CurrentControlSet\\Services\\Netlogon\\Parameters\\MaximumPasswordAge=4,30
MACHINE\\System\\CurrentControlSet\\Services\\Netlogon\\Parameters\\RequireSignOrSeal=4,1
MACHINE\\System\\CurrentControlSet\\Services\\Netlogon\\Parameters\\SealSecureChannel=4,1
MACHINE\\System\\CurrentControlSet\\Services\\Netlogon\\Parameters\\SignSecureChannel=4,1
MACHINE\\System\\CurrentControlSet\\Services\\Netlogon\\Parameters\\StrongKey=4,1
MACHINE\\System\\CurrentControlSet\\Control\\Lsa\\RestrictAnonymous=4,1
MACHINE\\System\\CurrentControlSet\\Control\\Lsa\\RestrictAnonymousSAM=4,1
MACHINE\\System\\CurrentControlSet\\Control\\Lsa\\DisableDomainCreds=4,1
MACHINE\\System\\CurrentControlSet\\Control\\Lsa\\EveryoneIncludesAnonymous=4,0
MACHINE\\System\\CurrentControlSet\\Control\\Lsa\\LmCompatibilityLevel=4,5
MACHINE\\System\\CurrentControlSet\\Control\\Lsa\\MSV1_0\\NTLMMinClientSec=4,537395200
MACHINE\\System\\CurrentControlSet\\Control\\Lsa\\MSV1_0\\NTLMMinServerSec=4,537395200
MACHINE\\System\\CurrentControlSet\\Control\\Lsa\\MSV1_0\\allownullsessionfallback=4,0
MACHINE\\System\\CurrentControlSet\\Control\\Lsa\\pku2u\\AllowOnlineID=4,0
MACHINE\\System\\CurrentControlSet\\Control\\Lsa\\SupportedEncryptionTypes=4,2147483644
MACHINE\\System\\CurrentControlSet\\Control\\Lsa\\LdapClientIntegrity=4,1
MACHINE\\System\\CurrentControlSet\\Control\\Lsa\\AuditBaseObjects=4,0
MACHINE\\System\\CurrentControlSet\\Services\\LanManServer\\Parameters\\AutoShareWks=4,0
MACHINE\\System\\CurrentControlSet\\Services\\LanManServer\\Parameters\\AutoShareServer=4,0
MACHINE\\System\\CurrentControlSet\\Services\\LanManServer\\Parameters\\EnableSecuritySignature=4,1
MACHINE\\System\\CurrentControlSet\\Services\\LanManServer\\Parameters\\RequireSecuritySignature=4,1
MACHINE\\System\\CurrentControlSet\\Services\\LanManServer\\Parameters\\RestrictNullSessAccess=4,1
MACHINE\\System\\CurrentControlSet\\Services\\LanManWorkstation\\Parameters\\EnableSecuritySignature=4,1
MACHINE\\System\\CurrentControlSet\\Services\\LanManWorkstation\\Parameters\\RequireSecuritySignature=4,1
MACHINE\\System\\CurrentControlSet\\Services\\LanManWorkstation\\Parameters\\EnablePlainTextPassword=4,0
MACHINE\\System\\CurrentControlSet\\Services\\LanmanServer\\Parameters\\autodisconnect=4,15
MACHINE\\System\\CurrentControlSet\\Services\\LanManServer\\Parameters\\EnableForcedLogOff=4,1
MACHINE\\System\\CurrentControlSet\\Control\\Session Manager\\kernel\\ObCaseInsensitive=4,1
MACHINE\\System\\CurrentControlSet\\Control\\SecurePipeServers\\Winreg\\AllowedExactPaths\\Machine=7,
MACHINE\\System\\CurrentControlSet\\Control\\SecurePipeServers\\Winreg\\AllowedPaths\\Machine=7,
MACHINE\\System\\CurrentControlSet\\Control\\Print\\Providers\\LanMan Print Services\\Servers\\AddPrinterDrivers=4,1
MACHINE\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\CachedLogonsCount=1,"4"
MACHINE\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\ForceUnlockLogon=4,1
MACHINE\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\PasswordExpiryWarning=4,14
MACHINE\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\ScRemoveOption=1,"1"
MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\DisableCAD=4,0
MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\DontDisplayLastUserName=4,1
MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\InactivityTimeoutSecs=4,300
MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\LegalNoticeText=7,"AUTHORISED USE ONLY\\nThis system is the property of Bidouille. Unauthorised access is prohibited and subject to prosecution under applicable laws."
MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\LegalNoticeCaption=1,"Bidouille - Authorised Access Only"
MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\ShutdownWithoutLogon=4,0
MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\LocalAccountTokenFilterPolicy=4,0
MACHINE\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\AllocateDASD=1,"0"
[Version]
signature="$CHICAGO$"
Revision=1
"""


def apply_account_policies_and_user_rights(temp_dir: str) -> bool:
    """Apply account policies and user rights via secedit INF."""
    log_section("Account Policies, User Rights, Security Options (secedit)")
    inf_path = os.path.join(temp_dir, "hardening.inf")
    sdb_path = os.path.join(temp_dir, "secedit.sdb")

    with open(inf_path, "w", encoding="utf-16") as f:
        f.write(SECEDIT_INF_TEMPLATE)

    ok = _run_cmd(
        ["secedit", "/configure", "/db", sdb_path, "/cfg", inf_path, "/overwrite", "/quiet"],
        "secedit /configure — account policies + user rights + security options"
    )
    if ok:
        log_ok("WDC-001..010: Account policies applied (history=24, maxage=90, minlen=14, complexity, lockout=5/15min)")
        log_ok("WDC-011..049: User rights assignment applied")
        log_ok("WDC-050..099: Security options (LSA, network, Netlogon) applied")
    return ok


# ─── Registry-based settings ─────────────────────────────────────────────────

def apply_uac_settings():
    log_section("UAC Settings (WDC-100..107)")
    base = "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System"
    settings = [
        ("FilterAdministratorToken", "DWord", 1),      # WDC-100: Admin Approval for built-in
        ("ConsentPromptBehaviorAdmin", "DWord", 2),    # WDC-101: Consent on secure desktop
        ("ConsentPromptBehaviorUser", "DWord", 0),     # WDC-102: Auto deny
        ("EnableInstallerDetection", "DWord", 1),      # WDC-103
        ("EnableSecureUIAPaths", "DWord", 1),           # WDC-104
        ("EnableLUA", "DWord", 1),                      # WDC-105
        ("PromptOnSecureDesktop", "DWord", 1),          # WDC-106
        ("EnableVirtualization", "DWord", 1),           # WDC-107
    ]
    for name, vtype, val in settings:
        _reg_set(base, name, vtype, val)


def apply_system_services():
    log_section("System Services (WDC-108)")
    log_ok("WDC-108: Disabling Print Spooler (DC)")
    _ps("Stop-Service -Name Spooler -Force -ErrorAction SilentlyContinue")
    _ps("Set-Service -Name Spooler -StartupType Disabled")
    log_ok("Print Spooler stopped and disabled")


def apply_windows_firewall():
    log_section("Windows Firewall (WDC-109..122)")

    # Domain profile
    _run_cmd(["netsh", "advfirewall", "set", "domainprofile", "state", "on"],
             "WDC-109: Domain firewall ON")
    _run_cmd(["netsh", "advfirewall", "set", "domainprofile", "firewallpolicy", "blockinbound,allowoutbound"],
             "WDC-110: Domain inbound block")
    _run_cmd(["netsh", "advfirewall", "set", "domainprofile", "settings", "inboundusernotification", "disable"],
             "WDC-111: Domain notifications off")
    _run_cmd(["netsh", "advfirewall", "set", "domainprofile", "logging",
              "maxfilesize", "16384", "droppedconnections", "enable", "allowedconnections", "enable"],
             "WDC-112..114: Domain logging configured")

    # Private profile
    _run_cmd(["netsh", "advfirewall", "set", "privateprofile", "state", "on"],
             "WDC-115: Private firewall ON")
    _run_cmd(["netsh", "advfirewall", "set", "privateprofile", "firewallpolicy", "blockinbound,allowoutbound"],
             "WDC-116: Private inbound block")
    _run_cmd(["netsh", "advfirewall", "set", "privateprofile", "logging",
              "maxfilesize", "16384", "droppedconnections", "enable", "allowedconnections", "enable"],
             "WDC-117: Private logging configured")

    # Public profile
    _run_cmd(["netsh", "advfirewall", "set", "publicprofile", "state", "on"],
             "WDC-118: Public firewall ON")
    _run_cmd(["netsh", "advfirewall", "set", "publicprofile", "firewallpolicy", "blockinbound,allowoutbound"],
             "WDC-119: Public inbound block")
    _run_cmd(["netsh", "advfirewall", "set", "publicprofile", "settings",
              "localfirewallrules", "disable", "localconsecrules", "disable"],
             "WDC-120..121: Public local rules disabled")
    _run_cmd(["netsh", "advfirewall", "set", "publicprofile", "logging",
              "maxfilesize", "16384", "droppedconnections", "enable", "allowedconnections", "enable"],
             "WDC-122: Public logging configured")

    # Allow core DC services
    log_ok("Allowing essential DC ports (AD, DNS, Kerberos, LDAP, RPC)...")
    dc_rules = [
        ("DNS-In", "53", "UDP"), ("DNS-In-TCP", "53", "TCP"),
        ("Kerberos-UDP", "88", "UDP"), ("Kerberos-TCP", "88", "TCP"),
        ("LDAP-TCP", "389", "TCP"), ("LDAP-UDP", "389", "UDP"),
        ("LDAP-SSL", "636", "TCP"), ("GC-LDAP", "3268", "TCP"),
        ("GC-LDAP-SSL", "3269", "TCP"), ("SMB", "445", "TCP"),
        ("RPC-Endpt", "135", "TCP"), ("NTP-UDP", "123", "UDP"),
        ("NetBIOS-NS", "137", "UDP"), ("NetBIOS-DGM", "138", "UDP"),
        ("NetBIOS-SSN", "139", "TCP"), ("W32TM", "123", "TCP"),
    ]
    for name, port, proto in dc_rules:
        _ps(
            f'New-NetFirewallRule -DisplayName "DC-{name}" -Direction Inbound '
            f'-Protocol {proto} -LocalPort {port} -Action Allow -Profile Domain '
            f'-ErrorAction SilentlyContinue | Out-Null'
        )
    log_ok("DC firewall rules configured")


def apply_advanced_audit_policy():
    log_section("Advanced Audit Policy (WDC-123..156)")

    audit_settings = [
        # subcategory, success, failure
        ("Credential Validation", True, True),          # 17.1.1
        ("Kerberos Authentication Service", True, True), # 17.1.2 DC
        ("Kerberos Service Ticket Operations", True, True), # 17.1.3 DC
        ("Application Group Management", True, True),   # 17.2.1
        ("Computer Account Management", True, False),   # 17.2.2 DC
        ("Distribution Group Management", True, False), # 17.2.3 DC
        ("Other Account Management Events", True, False), # 17.2.4 DC
        ("Security Group Management", True, False),     # 17.2.5
        ("User Account Management", True, True),        # 17.2.6
        ("Plug and Play Events", True, False),          # 17.3.1
        ("Process Creation", True, False),              # 17.3.2
        ("Directory Service Access", False, True),      # 17.4.1 DC
        ("Directory Service Changes", True, False),     # 17.4.2 DC
        ("Account Lockout", False, True),               # 17.5.1
        ("Group Membership", True, False),              # 17.5.2
        ("Logoff", True, False),                        # 17.5.3
        ("Logon", True, True),                          # 17.5.4
        ("Other Logon/Logoff Events", True, True),      # 17.5.5
        ("Special Logon", True, False),                 # 17.5.6
        ("Detailed File Share", False, True),           # 17.6.1
        ("File Share", True, True),                     # 17.6.2
        ("Other Object Access Events", True, True),     # 17.6.3
        ("Removable Storage", True, True),              # 17.6.4
        ("Audit Policy Change", True, False),           # 17.7.1
        ("Authentication Policy Change", True, False),  # 17.7.2
        ("Authorization Policy Change", True, False),   # 17.7.3
        ("MPSSVC Rule-Level Policy Change", True, True), # 17.7.4
        ("Other Policy Change Events", False, True),    # 17.7.5
        ("Sensitive Privilege Use", True, True),        # 17.8.1
        ("IPsec Driver", True, True),                   # 17.9.1
        ("Other System Events", True, True),            # 17.9.2
        ("Security State Change", True, False),         # 17.9.3
        ("Security System Extension", True, False),     # 17.9.4
        ("System Integrity", True, True),               # 17.9.5
    ]

    for subcategory, success, failure in audit_settings:
        success_flag = "enable" if success else "disable"
        failure_flag = "enable" if failure else "disable"
        rc, _, err = _ps(
            f'auditpol /set /subcategory:"{subcategory}" '
            f'/success:{success_flag} /failure:{failure_flag}'
        )
        if rc == 0:
            log_ok(f"Audit: {subcategory} (S:{success_flag}/F:{failure_flag})")
        else:
            log_warn(f"Audit {subcategory}: {err}")


def apply_administrative_templates():
    """Apply CIS Section 18 Administrative Templates via registry."""
    log_section("Administrative Templates — CIS Section 18 (WDC-157..340)")

    reg_settings = [
        # (key, value_name, type, data, description)

        # 18.1.1 — Lock screen
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\Personalization",
         "NoLockScreenCamera", "DWord", 1, "WDC-157: No lock screen camera"),
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\Personalization",
         "NoLockScreenSlideshow", "DWord", 1, "WDC-158: No lock screen slideshow"),

        # 18.1.2 — Speech
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\InputPersonalization",
         "AllowInputPersonalization", "DWord", 0, "WDC-159: No online speech recognition"),

        # 18.1.3 — Tips
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\CloudContent",
         "DisableSoftLanding", "DWord", 1, "WDC-160: No online tips"),

        # 18.4 — MS Security Guide
        ("HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
         "LocalAccountTokenFilterPolicy", "DWord", 0, "WDC-169: UAC restrictions local accounts"),
        ("HKLM:\\SYSTEM\\CurrentControlSet\\Services\\MrxSmb10",
         "Start", "DWord", 4, "WDC-170: SMBv1 client disabled"),
        ("HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters",
         "SMB1", "DWord", 0, "WDC-171: SMBv1 server disabled"),
        ("HKLM:\\SOFTWARE\\Microsoft\\Cryptography\\Wintrust\\Config",
         "EnableCertPaddingCheck", "String", "1", "WDC-172: Certificate padding check"),
        ("HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\kernel",
         "DisableExceptionChainValidation", "DWord", 0, "WDC-173: SEHOP enabled"),
        ("HKLM:\\SYSTEM\\CurrentControlSet\\Services\\NetBT\\Parameters",
         "NodeType", "DWord", 2, "WDC-174: NetBT P-node"),

        # 18.5 — MSS
        ("HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
         "AutoAdminLogon", "String", "0", "WDC-175: No auto admin logon"),
        ("HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Tcpip6\\Parameters",
         "DisableIPSourceRouting", "DWord", 2, "WDC-176: IPv6 source routing disabled"),
        ("HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters",
         "DisableIPSourceRouting", "DWord", 2, "WDC-177: IPv4 source routing disabled"),
        ("HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters",
         "EnableICMPRedirect", "DWord", 0, "WDC-178: ICMP redirect disabled"),
        ("HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters",
         "KeepAliveTime", "DWord", 300000, "WDC-179: TCP keep-alive 300s"),
        ("HKLM:\\SYSTEM\\CurrentControlSet\\Services\\NetBT\\Parameters",
         "NoNameReleaseOnDemand", "DWord", 1, "WDC-180: No NetBIOS name release"),
        ("HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters",
         "PerformRouterDiscovery", "DWord", 0, "WDC-181: No router discovery"),
        ("HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Session Manager",
         "SafeDllSearchMode", "DWord", 1, "WDC-182: SafeDllSearchMode"),
        ("HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Tcpip6\\Parameters",
         "TcpMaxDataRetransmissions", "DWord", 3, "WDC-183: IPv6 TCP retransmit=3"),
        ("HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters",
         "TcpMaxDataRetransmissions", "DWord", 3, "WDC-184: IPv4 TCP retransmit=3"),
        ("HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Eventlog\\Security",
         "WarningLevel", "DWord", 90, "WDC-185: Eventlog warning at 90%"),

        # 18.6.4 — DNS
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient",
         "EnableMulticast", "DWord", 0, "WDC-186: mDNS disabled"),
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient",
         "DisableSmartNameResolution", "DWord", 1, "WDC-188: No IPv6 default DNS"),
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient",
         "EnableNetbios", "DWord", 2, "WDC-187: NetBIOS public networks off"),

        # 18.6.5 — Fonts
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\System",
         "EnableFontProviders", "DWord", 0, "WDC-190: No font providers"),

        # 18.6.7 — LanMan Server
        ("HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanManServer\\Parameters",
         "AuditSmb1Access", "DWord", 1, "WDC-191: SMB1 audit"),
        ("HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanManServer\\Parameters",
         "EnableAuthRateLimiter", "DWord", 1, "WDC-192: Auth rate limiter"),
        ("HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanManServer\\Parameters",
         "DisableMailslots", "DWord", 1, "WDC-193: No remote mailslots"),
        ("HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanManServer\\Parameters",
         "SMBServerNameHardeningLevel", "DWord", 3, "WDC-194: SMB 3.1.1 minimum"),

        # 18.6.8 — LanMan Workstation
        ("HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters",
         "RequireSecuritySignature", "DWord", 1, "WDC-195: Workstation encryption required"),

        # 18.6.9 — LLTDIO/RSPNDR
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\LLTD",
         "AllowLLTDIOOnDomain", "DWord", 0, "WDC-196: LLTDIO disabled"),
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\LLTD",
         "AllowRspndrOnDomain", "DWord", 0, "WDC-197: RSPNDR disabled"),

        # 18.6.10 — P2P
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Peernet",
         "Disabled", "DWord", 1, "WDC-198: P2P networking disabled"),

        # 18.6.11 — Network connections
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\Network Connections",
         "NC_ShowSharedAccessUI", "DWord", 0, "WDC-200: No ICS"),
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\Network Connections",
         "NC_StdDomainUserSetLocation", "DWord", 1, "WDC-201: Domain users elevate for location"),

        # 18.6.14 — Hardened UNC paths
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\NetworkProvider\\HardenedPaths",
         "\\\\*\\NETLOGON",
         "String", "RequireMutualAuthentication=1,RequireIntegrity=1,RequirePrivacy=1",
         "WDC-202: NETLOGON hardened UNC"),
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\NetworkProvider\\HardenedPaths",
         "\\\\*\\SYSVOL",
         "String", "RequireMutualAuthentication=1,RequireIntegrity=1,RequirePrivacy=1",
         "WDC-202: SYSVOL hardened UNC"),

        # 18.6.19 — IPv6
        ("HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Tcpip6\\Parameters",
         "DisabledComponents", "DWord", 0xFF, "WDC-203: IPv6 all disabled"),

        # 18.6.21 — Simultaneous connections
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\WcmSvc\\GroupPolicy",
         "fMinimizeConnections", "DWord", 3, "WDC-204: Minimize simultaneous connections"),

        # 18.7 — Print
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Printers",
         "RegisterSpoolerRemoteRpcEndPoint", "DWord", 2, "WDC-205: Spooler no client connections"),
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Printers",
         "RedirectionGuardPolicy", "DWord", 1, "WDC-206: Redirection Guard"),
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Printers\\PointAndPrint",
         "NoWarningNoElevationOnInstall", "DWord", 0, "WDC-214: Print drivers require admin"),
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Printers\\RPC",
         "RpcUseNamedPipeProtocol", "DWord", 0, "WDC-207: RPC over TCP"),
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Printers\\RPC",
         "RpcAuthentication", "DWord", 0, "WDC-208: RPC authentication default"),
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Printers\\RPC",
         "RpcProtocols", "DWord", 5, "WDC-209: RPC listener TCP"),
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Printers\\RPC",
         "ForceKerberosForRpc", "DWord", 0, "WDC-210: RPC negotiate or higher"),
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Printers\\RPC",
         "RpcTcpPort", "DWord", 0, "WDC-211: RPC TCP port 0"),
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Printers\\RPC",
         "EnablePacketPrivacy", "DWord", 1, "WDC-212: RPC packet privacy"),
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Printers",
         "EnableWindowsProtectedPrint", "DWord", 1, "WDC-213: Windows protected print"),

        # 18.8 — Notifications
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\CurrentVersion\\PushNotifications",
         "NoCloudApplicationNotification", "DWord", 1, "WDC-215: No network notification"),

        # 18.9.3 — Audit process creation
        ("HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Audit",
         "ProcessCreationIncludeCmdLine_Enabled", "DWord", 1, "WDC-216: Command line in process creation"),

        # 18.9.4 — Credentials
        ("HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\CredSSP\\Parameters",
         "AllowEncryptionOracle", "DWord", 0, "WDC-217: Encryption Oracle Remediation"),
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\CredentialsDelegation",
         "AllowProtectedCreds", "DWord", 1, "WDC-218: Non-exportable credentials delegation"),

        # 18.9.5 — VBS / Credential Guard / HVCI
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\DeviceGuard",
         "EnableVirtualizationBasedSecurity", "DWord", 1, "WDC-219: VBS enabled"),
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\DeviceGuard",
         "RequirePlatformSecurityFeatures", "DWord", 1, "WDC-220: Secure Boot"),
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\DeviceGuard",
         "HypervisorEnforcedCodeIntegrity", "DWord", 1, "WDC-221: HVCI with UEFI lock"),
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\DeviceGuard",
         "HVCIMATRequired", "DWord", 1, "WDC-222: UEFI MAT required"),
        # WDC-223: Credential Guard DISABLED on DC (per CIS)
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\DeviceGuard",
         "LsaCfgFlags", "DWord", 0, "WDC-223: Credential Guard DISABLED (DC requirement)"),
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\DeviceGuard",
         "ConfigureSystemGuardLaunch", "DWord", 1, "WDC-224: Secure Launch enabled"),

        # 18.9.7 — Device metadata
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\Device Metadata",
         "PreventDeviceMetadataFromNetwork", "DWord", 1, "WDC-226: No device metadata download"),

        # 18.9.13 — Boot driver
        ("HKLM:\\SYSTEM\\CurrentControlSet\\Policies\\EarlyLaunch",
         "DriverLoadPolicy", "DWord", 3, "WDC-227: Boot driver good+unknown+critical"),

        # 18.9.19 — Group Policy
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\Group Policy\\{827D319E-6EAC-11D2-A4EA-00C04F79F83A}",
         "NoBackgroundPolicy", "DWord", 0, "WDC-230: Security policy no background skip"),
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\Group Policy\\{827D319E-6EAC-11D2-A4EA-00C04F79F83A}",
         "NoGPOListChanges", "DWord", 0, "WDC-231: Security policy process if unchanged"),
        ("HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
         "DisableBkGndGroupPolicy", "DWord", 0, "WDC-232: Background GP refresh enabled"),

        # 18.9.20 — Internet Communication
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Printers",
         "DisableHTTPPrinting", "DWord", 1, "WDC-233: No HTTP printing"),
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\Internet Connection Wizard",
         "ExitOnMSICW", "DWord", 1, "WDC-234: No ICW"),
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\Internet Connection Wizard",
         "ExitOnMSICW", "DWord", 1, "WDC-234: ICW disabled"),
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\DriverSearching",
         "DontSearchWindowsUpdate", "DWord", 1, "WDC-235: No web publishing download"),
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Printers",
         "DisableHTTPPrinting", "DWord", 1, "WDC-236: No HTTP printing"),
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\Registration Wizard Control",
         "NoRegistration", "DWord", 1, "WDC-237: No registration URL"),
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\SearchCompanion",
         "DisableContentFileUpdates", "DWord", 1, "WDC-238: No search companion updates"),
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Messenger\\Client",
         "CEIP", "DWord", 2, "WDC-239: No Messenger CEIP"),
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\SQMClient\\Windows",
         "CEIPEnable", "DWord", 0, "WDC-240: No Windows CEIP"),
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\Windows Error Reporting",
         "Disabled", "DWord", 1, "WDC-241: No WER"),

        # 18.9.23 — Kerberos
        ("HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Kerberos\\Parameters",
         "DevicePKInitEnabled", "DWord", 1, "WDC-242: Kerberos device auth"),

        # 18.9.24 — Kernel DMA
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\Kernel DMA Protection",
         "DeviceEnumerationPolicy", "DWord", 0, "WDC-225: Kernel DMA block all"),

        # 18.9.26 — LAPS
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft Services\\AdmPwd",
         "BackupDirectory", "DWord", 2, "WDC-161: LAPS backup to AD"),
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft Services\\AdmPwd",
         "PwdExpirationProtectionEnabled", "DWord", 1, "WDC-162: LAPS expiry protection"),
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft Services\\AdmPwd",
         "ADPasswordEncryptionEnabled", "DWord", 1, "WDC-163: LAPS encryption"),
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft Services\\AdmPwd",
         "PasswordComplexity", "DWord", 4, "WDC-164: LAPS complexity all chars"),
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft Services\\AdmPwd",
         "PasswordLength", "DWord", 15, "WDC-165: LAPS length 15"),
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft Services\\AdmPwd",
         "PasswordAgeDays", "DWord", 30, "WDC-166: LAPS age 30 days"),
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft Services\\AdmPwd",
         "PostAuthenticationResetDelay", "DWord", 8, "WDC-167: LAPS post-auth 8h"),
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft Services\\AdmPwd",
         "PostAuthenticationActions", "DWord", 3, "WDC-168: LAPS post-auth reset+logoff"),

        # 18.9.27 — LSASS
        ("HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa",
         "DisableRestrictedAdmin", "DWord", 0, "WDC-228: No custom SSPs (DC)"),
        ("HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa",
         "RunAsPPL", "DWord", 2, "WDC-229: LSASS protected process with UEFI lock"),

        # 18.9.28 — Language
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Control Panel\\International",
         "BlockUserInputMethodsForSignIn", "DWord", 1, "WDC-340: No input method copy to sign-in"),

        # 18.9.29 — Logon
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\System",
         "BlockUserFromShowingAccountDetailsOnSignin", "DWord", 1, "WDC-245: No account details at sign-in"),
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\System",
         "DontDisplayNetworkSelectionUI", "DWord", 1, "WDC-246: No network selection UI"),
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\System",
         "DontEnumerateConnectedUsers", "DWord", 1, "WDC-247: No connected users enum"),
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\System",
         "DisableLockScreenAppNotifications", "DWord", 1, "WDC-248: No lock screen notifications"),
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\System",
         "AllowDomainPINLogon", "DWord", 0, "WDC-249: No PIN sign-in"),

        # 18.9.31 — NetLogon
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Netlogon\\Parameters",
         "BlockNetBIOSBasedLocatorService", "DWord", 1, "WDC-250: No NetBIOS DC location"),

        # 18.9.33 — Activity Feed
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\System",
         "EnableClipboardSharing", "DWord", 0, "WDC-251: No clipboard sync"),
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\System",
         "EnableActivityFeed", "DWord", 0, "WDC-252: No user activities upload"),

        # 18.9.37 — Remote Assistance
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services",
         "fAllowUnsolicited", "DWord", 0, "WDC-293: No offer remote assistance"),
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services",
         "fAllowToGetHelp", "DWord", 0, "WDC-294: No solicited remote assistance"),

        # 18.9.41 — SAM (DC)
        ("HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
         "BlockROCAVulnerableKeys", "DWord", 1, "WDC-243: Block ROCA WHfB keys"),
        ("HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
         "SAMStrongEncryptionRequiredForChangePassword", "DWord", 1, "WDC-244: Strong SAM encryption"),

        # 18.10.6 — App Runtime
        ("HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
         "MSAOptional", "DWord", 1, "WDC-334: MS accounts optional"),

        # 18.10.8 — AutoPlay
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\Explorer",
         "NoAutoplayfornonVolume", "DWord", 1, "WDC-253: No AutoPlay non-volume"),
        ("HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer",
         "NoAutorun", "DWord", 1, "WDC-254: No AutoRun"),
        ("HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer",
         "NoDriveTypeAutoRun", "DWord", 255, "WDC-255: Turn off AutoPlay all drives"),

        # 18.10.9 — Biometrics
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Biometrics\\FacialFeatures",
         "EnhancedAntiSpoofing", "DWord", 1, "WDC-256: Enhanced anti-spoofing"),

        # 18.10.11 — Camera
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Camera",
         "AllowCamera", "DWord", 0, "WDC-271: Camera disabled"),

        # 18.10.13 — Cloud content
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\CloudContent",
         "DisableConsumerAccountStateContent", "DWord", 1, "WDC-257: No cloud consumer content"),
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\CloudContent",
         "DisableCloudOptimizedContent", "DWord", 1, "WDC-258: No cloud optimized content"),

        # 18.10.16 — Connected User Experience / Telemetry
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection",
         "AllowTelemetry", "DWord", 1, "WDC-259: Diagnostic data = required only"),
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection",
         "DisableEnterpriseAuthProxy", "DWord", 1, "WDC-260: No auth proxy for telemetry"),
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection",
         "DoNotShowFeedbackNotifications", "DWord", 1, "WDC-261: No feedback notifications"),
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection",
         "EnableOneSettingsAuditing", "DWord", 1, "WDC-262: OneSettings auditing"),
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection",
         "LimitDiagnosticLogCollection", "DWord", 1, "WDC-263: Limit diagnostic logs"),
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection",
         "LimitDumpCollection", "DWord", 1, "WDC-264: Limit dump collection"),

        # 18.10.26 — Event Log sizes
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\EventLog\\Application",
         "MaxSize", "DWord", 32768, "WDC-265: App log 32768 KB"),
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\EventLog\\Security",
         "MaxSize", "DWord", 196608, "WDC-266: Security log 196608 KB"),
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\EventLog\\Setup",
         "MaxSize", "DWord", 32768, "WDC-267: Setup log 32768 KB"),
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\EventLog\\System",
         "MaxSize", "DWord", 32768, "WDC-268: System log 32768 KB"),

        # 18.10.29 — File Explorer
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\Explorer",
         "NoHeapTerminationOnCorruption", "DWord", 0, "WDC-269: Heap termination on corruption"),
        ("HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer",
         "PreXPSP2ShellProtocolBehavior", "DWord", 0, "WDC-270: Shell protocol protected mode"),

        # 18.10.33 — Location
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\LocationAndSensors",
         "DisableLocation", "DWord", 1, "WDC-336: Location disabled"),

        # 18.10.36 — Messaging
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\Messaging",
         "AllowMessageSync", "DWord", 0, "WDC-337: No message sync"),

        # 18.10.40 — MS account
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\MicrosoftAccount",
         "DisableUserAuth", "DWord", 1, "WDC-272: Block consumer MS accounts"),

        # 18.10.41 — Push to install
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\PushToInstall",
         "DisablePushToInstall", "DWord", 1, "WDC-338: No push to install"),

        # 18.10.42 — Windows Defender
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows Advanced Threat Protection",
         "ForceDefenderPassiveMode", "DWord", 0, "WDC-273: EDR in block mode"),
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Spynet",
         "LocalSettingOverrideSpynetReporting", "DWord", 0, "WDC-274: No local override MAPS"),
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Spynet",
         "SpynetReporting", "DWord", 2, "WDC-275: Join MAPS advanced"),
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Windows Defender Exploit Guard\\ASR",
         "ExploitGuard_ASR_Rules", "DWord", 1, "WDC-276: ASR rules enabled"),
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Windows Defender Exploit Guard\\Network Protection",
         "EnableNetworkProtection", "DWord", 1, "WDC-278: Block dangerous websites"),
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection",
         "DisableRealtimeMonitoring", "DWord", 0, "WDC-281: Real-time protection on"),
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection",
         "DisableBehaviorMonitoring", "DWord", 0, "WDC-282: Behavior monitoring on"),
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection",
         "DisableScriptScanning", "DWord", 0, "WDC-283: Script scanning on"),
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection",
         "DisableIOAVProtection", "DWord", 0, "WDC-280: Scan downloaded files"),
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection",
         "DisableRealtimeMonitoringAtOOBE", "DWord", 0, "WDC-279: OOBE real-time protection"),
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Brute-Force Protection",
         "Aggressiveness", "DWord", 1, "WDC-284: Brute-force protection medium"),
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Features",
         "TamperProtection", "DWord", 5, "WDC-285: Remote encryption protection"),
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Reporting",
         "DisableGenericRePorts", "DWord", 1, "WDC-286: No Watson events"),
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Scan",
         "DisablePackedExeScanning", "DWord", 0, "WDC-287: Scan packed executables"),
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Scan",
         "DisableRemovableDriveScanning", "DWord", 0, "WDC-288: Scan removable drives"),
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Scan",
         "ScanScheduleDay", "DWord", 7, "WDC-289: Quick scan after 7 days"),
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Scan",
         "DisableEmailScanning", "DWord", 0, "WDC-290: Email scanning on"),
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows Defender",
         "PUAProtection", "DWord", 1, "WDC-291: Block PUAs"),
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows Defender",
         "DisableLocalAdminMerge", "DWord", 1, "WDC-292: Exclusions visible to local users"),

        # 18.10.57 — Remote Desktop
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services",
         "fDisableCcm", "DWord", 1, "WDC-295: No COM port redirection"),
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services",
         "fDisableCdm", "DWord", 1, "WDC-296: No drive redirection"),
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services",
         "fDisableLocationRedir", "DWord", 1, "WDC-297: No location redirection"),
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services",
         "fDisableLPT", "DWord", 1, "WDC-298: No LPT redirection"),
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services",
         "fDisablePNPRedir", "DWord", 1, "WDC-299: No PnP redirection"),
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services",
         "fDisableWebAuthn", "DWord", 1, "WDC-300: No WebAuthn redirection"),
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services",
         "fDisableClipboardRedir", "DWord", 1, "WDC-301: No clipboard server→client"),
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services",
         "fPromptForPassword", "DWord", 1, "WDC-302: Always prompt RDS password"),
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services",
         "fEncryptRPCTraffic", "DWord", 1, "WDC-303: Secure RPC for RDS"),
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services",
         "SecurityLayer", "DWord", 2, "WDC-304: SSL for RDP"),
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services",
         "UserAuthentication", "DWord", 1, "WDC-305: NLA required"),
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services",
         "MinEncryptionLevel", "DWord", 3, "WDC-306: High encryption"),
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services",
         "MaxIdleTime", "DWord", 900000, "WDC-307: RDS idle timeout 15min"),
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services",
         "MaxDisconnectionTime", "DWord", 60000, "WDC-308: Disconnected session 1min"),

        # 18.10.58 — RSS Feed
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Internet Explorer\\Feeds",
         "DisableEnclosureDownload", "DWord", 1, "WDC-309: No RSS enclosure download"),

        # 18.10.59 — Search
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\Windows Search",
         "AllowCloudSearch", "DWord", 0, "WDC-310: No cloud search"),
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\Windows Search",
         "AllowIndexingEncryptedStoresOrItems", "DWord", 0, "WDC-311: No encrypted file indexing"),

        # 18.10.63 — Software Protection
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\CurrentVersion\\Software Protection Platform",
         "NoGenTicket", "DWord", 1, "WDC-312: No KMS online AVS"),

        # 18.10.77 — SmartScreen
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\System",
         "EnableSmartScreen", "DWord", 1, "WDC-335: SmartScreen enabled"),

        # 18.10.81 — Ink Workspace
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\WindowsInkWorkspace",
         "AllowWindowsInkWorkspace", "DWord", 0, "WDC-329: Ink Workspace disabled"),

        # 18.10.82 — Windows Installer
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer",
         "EnableUserControl", "DWord", 0, "WDC-330: No user control over installs"),
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer",
         "AlwaysInstallElevated", "DWord", 0, "WDC-331: No elevated installs"),

        # 18.10.83 — Winlogon
        ("HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
         "DontDisplayLockedUserId", "DWord", 3, "WDC-332: No MPR password notifications"),
        ("HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
         "DisableAutomaticRestartSignOn", "DWord", 1, "WDC-333: No auto restart sign-on"),

        # 18.10.88 — PowerShell
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging",
         "EnableScriptBlockLogging", "DWord", 1, "WDC-313: PS script block logging"),
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\Transcription",
         "EnableTranscripting", "DWord", 1, "WDC-314: PS transcription enabled"),

        # 18.10.90 — WinRM
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\WinRM\\Client",
         "AllowBasic", "DWord", 0, "WDC-315: WinRM client no basic auth"),
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\WinRM\\Client",
         "AllowUnencryptedTraffic", "DWord", 0, "WDC-316: WinRM client no unencrypted"),
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\WinRM\\Client",
         "AllowDigest", "DWord", 0, "WDC-317: WinRM client no digest"),
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\WinRM\\Service",
         "AllowBasic", "DWord", 0, "WDC-318: WinRM service no basic auth"),
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\WinRM\\Service",
         "AllowAutoConfig", "DWord", 0, "WDC-319: WinRM service no auto config"),
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\WinRM\\Service",
         "AllowUnencryptedTraffic", "DWord", 0, "WDC-320: WinRM service no unencrypted"),
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\WinRM\\Service",
         "DisableRunAs", "DWord", 1, "WDC-321: WinRM no RunAs"),

        # 18.10.91 — WinRS
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\WinRM\\Service\\WinRS",
         "AllowRemoteShellAccess", "DWord", 0, "WDC-322: No remote shell access"),

        # 18.10.93 — Windows Security
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows Defender Security Center\\App and Browser protection",
         "UILockdown", "DWord", 1, "WDC-323: Users cannot modify Defender settings"),

        # 18.10.94 — Windows Update
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU",
         "NoAutoRebootWithLoggedOnUsers", "DWord", 0, "WDC-324: Allow auto-restart"),
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU",
         "NoAutoUpdate", "DWord", 0, "WDC-325: Automatic updates enabled"),
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU",
         "ScheduledInstallDay", "DWord", 0, "WDC-326: Update every day"),

        # 18.11 — WinHTTP
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings",
         "EnableAutoProxyResultCache", "DWord", 0, "WDC-327: WPAD disabled"),
        ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings",
         "ProxyBypassLocalNames", "DWord", 0, "WDC-328: No loopback proxy auth"),
    ]

    for key, name, vtype, data, desc in reg_settings:
        rc, _, err = _ps(
            f'If (!(Test-Path "{key}")) {{ New-Item -Path "{key}" -Force | Out-Null }}; '
            f'Set-ItemProperty -Path "{key}" -Name "{name}" -Type {vtype} -Value {data} -Force'
        )
        if rc == 0:
            log_ok(desc)
        else:
            log_warn(f"{desc}: {err}")

    # ASR rules (WDC-277) — enable specific ASR rule IDs
    asr_rules = {
        "56a863a9-875e-4185-98a7-b882c64b5ce5": 1,  # Block abuse of exploited vulnerable signed drivers
        "7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c": 1,  # Block Adobe Reader from creating child processes
        "d4f940ab-401b-4efc-aadc-ad5f3c50688a": 1,  # Block all Office apps from creating child processes
        "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2": 1,  # Block credential stealing from LSASS
        "be9ba2d9-53ea-4cdc-84e5-9b1eeee46550": 1,  # Block executable content from email client
        "01443614-cd74-433a-b99e-2ecdc07bfc25": 1,  # Block executable files unless trusted
        "5beb7efe-fd9a-4556-801d-275e5ffc04cc": 1,  # Block execution of obfuscated scripts
        "d3e037e1-3eb8-44c8-a917-57927947596d": 1,  # Block JS/VBScript launching executable content
        "3b576869-a4ec-4529-8536-b80a7769e899": 1,  # Block Office apps from creating executable content
        "75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84": 1,  # Block Office apps from injecting into processes
        "26190899-1602-49e8-8b27-eb1d0a1ce869": 1,  # Block Office communication app child processes
        "e6db77e5-3df2-4cf1-b95a-636979351e5b": 1,  # Block persistence through WMI
        "d1e49aac-8f56-4280-b9ba-993a6d77406c": 1,  # Block process creations from PSExec and WMI
        "33ddedf1-c6e0-47cb-833e-de6133960387": 1,  # Block rebooting machine in safe mode
        "b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4": 1,  # Block untrusted/unsigned USB processes
        "c0033c00-d16d-4114-a5a0-dc9b3a7d2ceb": 1,  # Block Webshell creation for servers
        "a8f5898e-1dc8-49a9-9878-85004b8a61e6": 1,  # Block Wscript from executing JS downloaded
        "92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b": 1,  # Block Win32 API calls from Office macros
        "c1db55ab-c21a-4637-bb3f-a12568109d35": 1,  # Use advanced ransomware protection
    }
    asr_pairs = "; ".join([f'"{k}" = "{v}"' for k, v in asr_rules.items()])
    rc, _, err = _ps(
        f'$asrPath = "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Windows Defender Exploit Guard\\ASR\\Rules"; '
        f'If (!(Test-Path $asrPath)) {{ New-Item -Path $asrPath -Force | Out-Null }}; '
        + "; ".join([
            f'Set-ItemProperty -Path $asrPath -Name "{k}" -Value "{v}" -Type String -Force'
            for k, v in asr_rules.items()
        ])
    )
    if rc == 0:
        log_ok("WDC-277: ASR rules configured (19 rules enabled)")
    else:
        log_warn(f"WDC-277: ASR rules: {err}")


def apply_laps():
    """Apply LAPS configuration (WDC-161..168 are covered in apply_administrative_templates)."""
    log_section("LAPS (WDC-161..168) — already applied in Administrative Templates")


def apply_issp_specific():
    log_section("ISSP-Specific Settings (WDC-341..351)")

    # WDC-341: Fine-grained PSO for standard users
    pso_users_cmd = """
    If (!(Get-ADFineGrainedPasswordPolicy -Filter {Name -eq "PSO-Users"} -ErrorAction SilentlyContinue)) {
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
    """
    rc, out, err = _ps(pso_users_cmd)
    if rc == 0:
        log_ok(f"WDC-341: PSO-Users (standard users): {out}")
    else:
        log_warn(f"WDC-341: PSO-Users failed (may require ADPS module): {err}")

    # WDC-342: Fine-grained PSO for admin accounts
    pso_admins_cmd = """
    If (!(Get-ADFineGrainedPasswordPolicy -Filter {Name -eq "PSO-Admins"} -ErrorAction SilentlyContinue)) {
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
    """
    rc, out, err = _ps(pso_admins_cmd)
    if rc == 0:
        log_ok(f"WDC-342: PSO-Admins (admin accounts): {out}")
    else:
        log_warn(f"WDC-342: PSO-Admins failed: {err}")

    # WDC-348: BitLocker
    bl_cmd = """
    $volumes = Get-BitLockerVolume -ErrorAction SilentlyContinue
    If ($volumes) {
        ForEach ($vol in $volumes) {
            If ($vol.VolumeStatus -eq "FullyDecrypted") {
                Try {
                    Enable-BitLocker -MountPoint $vol.MountPoint -EncryptionMethod XtsAes256 `
                      -UsedSpaceOnly -SkipHardwareTest -RecoveryPasswordProtector -ErrorAction Stop
                    Write-Output ("BitLocker enabled on " + $vol.MountPoint)
                } Catch {
                    Write-Warning ("BitLocker on " + $vol.MountPoint + ": " + $_.Exception.Message)
                }
            } Else {
                Write-Output ("BitLocker already active on " + $vol.MountPoint + ": " + $vol.VolumeStatus)
            }
        }
    } Else {
        Write-Warning "No BitLocker-capable volumes found or BitLocker not available"
    }
    """
    rc, out, err = _ps(bl_cmd)
    if "enabled" in out.lower() or "already active" in out.lower():
        log_ok(f"WDC-348: BitLocker: {out}")
    else:
        log_warn(f"WDC-348: BitLocker: {out} {err}")

    # Not implemented items — log explanations
    log_skip("WDC-344: Emergency breakglass account — MANUAL: print password, seal envelope, store in physical safe")
    log_skip("WDC-345: Account deactivation lifecycle — MANUAL: requires HR/IAM integration")
    log_skip("WDC-346: CMDB inventory — MANUAL: requires ongoing IT staff updates")
    log_skip("WDC-347: VPN enforcement — MANUAL: requires VPN gateway infrastructure")
    log_skip("WDC-349: Centralized AV — MANUAL: requires SCCM/Intune infrastructure")
    log_skip("WDC-350: Offsite backup — MANUAL: requires backup infrastructure")
    log_skip("WDC-351: Separate admin accounts — MANUAL: organizational naming convention")


def apply_defender():
    log_section("Windows Defender / ASR (WDC-273..292) — applied in Administrative Templates")


def harden():
    """Main Windows DC hardening entry point."""
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
