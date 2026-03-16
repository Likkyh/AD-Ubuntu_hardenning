# IMPLEMENTATION — AD DC + Ubuntu Hardening

**Company**: Bidouille (automotive sector)
**ISSP**: ISO 27002 v2
**CIS Reference**: CIS Microsoft Windows Server 2025 Benchmark v2.0.0 — Level 1 DC
**Generated**: 2026-03-16 11:30:13

## Legend

- **Implemented**: Applied by the script
- **Not Implemented**: Not applied — reason given
- **Manual**: Procedural/organizational — cannot be automated

## Summary

| OS | Total | Implemented | Not Implemented | Manual |
|----|-------|-------------|-----------------|--------|
| Windows DC | 351 | 344 | 7 | 0 |
| Ubuntu | 113 | 107 | 6 | 0 |

---

## Windows DC Hardening (CIS L1 DC + ISSP)

| ID | Category | Hardening Point | Source | Status | Reason if Not Implemented |
|----|----------|-----------------|--------|--------|---------------------------|
| WDC-001 | Account Policy | Password history = 24 | CIS 1.1.1 | Implemented |  |
| WDC-002 | Account Policy | Max password age = 90 days | CIS 1.1.2 + ISSP §7.1 | Implemented |  |
| WDC-003 | Account Policy | Min password age = 1 day | CIS 1.1.3 | Implemented |  |
| WDC-004 | Account Policy | Min password length = 14 chars | CIS 1.1.4 | Implemented |  |
| WDC-005 | Account Policy | Password complexity = Enabled | CIS 1.1.5 | Implemented |  |
| WDC-006 | Account Policy | Relax min password length limits = Enabled | CIS 1.1.6 | Implemented |  |
| WDC-007 | Account Policy | Store passwords reversible encryption = Disabled | CIS 1.1.7 | Implemented |  |
| WDC-008 | Account Lockout | Account lockout duration = 15 min | CIS 1.2.1 | Implemented |  |
| WDC-009 | Account Lockout | Account lockout threshold = 5 | CIS 1.2.2 | Implemented |  |
| WDC-010 | Account Lockout | Reset lockout counter after = 15 min | CIS 1.2.4 | Implemented |  |
| WDC-011 | User Rights | Access Credential Manager = No One | CIS 2.2.1 | Implemented |  |
| WDC-012 | User Rights | Access computer from network (DC) = Admins, AuthUsers, EntDomainCtrlrs | CIS 2.2.2 | Implemented |  |
| WDC-013 | User Rights | Act as part of OS = No One | CIS 2.2.4 | Implemented |  |
| WDC-014 | User Rights | Add workstations to domain = Administrators | CIS 2.2.5 | Implemented |  |
| WDC-015 | User Rights | Adjust memory quotas = Admins, LOCAL SERVICE, NETWORK SERVICE | CIS 2.2.6 | Implemented |  |
| WDC-016 | User Rights | Allow log on locally (DC) = Admins, Enterprise Domain Controllers | CIS 2.2.7 | Implemented |  |
| WDC-017 | User Rights | Allow log on through RDS (DC) = Administrators | CIS 2.2.9 | Implemented |  |
| WDC-018 | User Rights | Back up files and directories = Administrators | CIS 2.2.11 | Implemented |  |
| WDC-019 | User Rights | Change system time = Admins, LOCAL SERVICE | CIS 2.2.12 | Implemented |  |
| WDC-020 | User Rights | Create a pagefile = Administrators | CIS 2.2.13 | Implemented |  |
| WDC-021 | User Rights | Create a token object = No One | CIS 2.2.14 | Implemented |  |
| WDC-022 | User Rights | Create global objects = Admins, LOCAL SERVICE, NETWORK SERVICE, SERVICE | CIS 2.2.15 | Implemented |  |
| WDC-023 | User Rights | Create permanent shared objects = No One | CIS 2.2.16 | Implemented |  |
| WDC-024 | User Rights | Create symbolic links (DC) = Administrators | CIS 2.2.17 | Implemented |  |
| WDC-025 | User Rights | Debug programs = Administrators | CIS 2.2.19 | Implemented |  |
| WDC-026 | User Rights | Deny access from network (DC) = Guests | CIS 2.2.20 | Implemented |  |
| WDC-027 | User Rights | Deny log on as batch job = Guests | CIS 2.2.22 | Implemented |  |
| WDC-028 | User Rights | Deny log on as service = Guests | CIS 2.2.23 | Implemented |  |
| WDC-029 | User Rights | Deny log on locally = Guests | CIS 2.2.24 | Implemented |  |
| WDC-030 | User Rights | Deny log on through RDS (DC) = Guests | CIS 2.2.25 | Implemented |  |
| WDC-031 | User Rights | Enable trusted delegation (DC) = Administrators | CIS 2.2.27 | Implemented |  |
| WDC-032 | User Rights | Force shutdown from remote = Administrators | CIS 2.2.29 | Implemented |  |
| WDC-033 | User Rights | Generate security audits = LOCAL SERVICE, NETWORK SERVICE | CIS 2.2.30 | Implemented |  |
| WDC-034 | User Rights | Impersonate client after auth (DC) = Admins, LOCAL SERVICE, NETWORK SERVICE, SERVICE | CIS 2.2.31 | Implemented |  |
| WDC-035 | User Rights | Increase scheduling priority = Admins, Window Manager Group | CIS 2.2.33 | Implemented |  |
| WDC-036 | User Rights | Load and unload device drivers = Administrators | CIS 2.2.34 | Implemented |  |
| WDC-037 | User Rights | Lock pages in memory = No One | CIS 2.2.35 | Implemented |  |
| WDC-038 | User Rights | Log on as batch job (DC) = Administrators | CIS 2.2.36 | Implemented |  |
| WDC-039 | User Rights | Manage auditing and security log (DC) = Administrators | CIS 2.2.37 | Implemented |  |
| WDC-040 | User Rights | Modify an object label = No One | CIS 2.2.39 | Implemented |  |
| WDC-041 | User Rights | Modify firmware environment values = Administrators | CIS 2.2.40 | Implemented |  |
| WDC-042 | User Rights | Perform volume maintenance tasks = Administrators | CIS 2.2.41 | Implemented |  |
| WDC-043 | User Rights | Profile single process = Administrators | CIS 2.2.42 | Implemented |  |
| WDC-044 | User Rights | Profile system performance = Admins, NT SERVICE\WdiServiceHost | CIS 2.2.43 | Implemented |  |
| WDC-045 | User Rights | Replace process level token = LOCAL SERVICE, NETWORK SERVICE | CIS 2.2.44 | Implemented |  |
| WDC-046 | User Rights | Restore files and directories = Administrators | CIS 2.2.45 | Implemented |  |
| WDC-047 | User Rights | Shut down the system = Administrators | CIS 2.2.46 | Implemented |  |
| WDC-048 | User Rights | Synchronize directory service data (DC) = No One | CIS 2.2.47 | Implemented |  |
| WDC-049 | User Rights | Take ownership of files = Administrators | CIS 2.2.48 | Implemented |  |
| WDC-050 | Security Options | Guest account status = Disabled | CIS 2.3.1.1 | Implemented |  |
| WDC-051 | Security Options | Local blank password = console only = Enabled | CIS 2.3.1.2 | Implemented |  |
| WDC-052 | Security Options | Rename administrator account | CIS 2.3.1.3 | Implemented |  |
| WDC-053 | Security Options | Rename guest account | CIS 2.3.1.4 | Implemented |  |
| WDC-054 | Security Options | Audit: Force subcategory settings = Enabled | CIS 2.3.2.1 | Implemented |  |
| WDC-055 | Security Options | Audit: Shut down if unable to log = Disabled | CIS 2.3.2.2 | Implemented |  |
| WDC-056 | Security Options | Devices: Prevent printer driver install = Enabled | CIS 2.3.4.1 | Implemented |  |
| WDC-057 | Security Options | DC: Allow server operators schedule tasks = Disabled | CIS 2.3.5.1 | Implemented |  |
| WDC-058 | Security Options | DC: LDAP server channel binding = Always | CIS 2.3.5.3 | Implemented |  |
| WDC-059 | Security Options | DC: LDAP server signing = Enabled | CIS 2.3.5.4 | Implemented |  |
| WDC-060 | Security Options | DC: Refuse machine account password changes = Disabled | CIS 2.3.5.5 | Implemented |  |
| WDC-061 | Security Options | Domain member: Digitally encrypt secure channel (always) = Enabled | CIS 2.3.6.1 | Implemented |  |
| WDC-062 | Security Options | Domain member: Digitally encrypt secure channel (when possible) = Enabled | CIS 2.3.6.2 | Implemented |  |
| WDC-063 | Security Options | Domain member: Digitally sign secure channel (when possible) = Enabled | CIS 2.3.6.3 | Implemented |  |
| WDC-064 | Security Options | Domain member: Disable machine account password changes = Disabled | CIS 2.3.6.4 | Implemented |  |
| WDC-065 | Security Options | Domain member: Max machine account password age = 30 days | CIS 2.3.6.5 | Implemented |  |
| WDC-066 | Security Options | Domain member: Require strong session key = Enabled | CIS 2.3.6.6 | Implemented |  |
| WDC-067 | Security Options | Interactive logon: Don't require CTRL+ALT+DEL = Disabled | CIS 2.3.7.1 | Implemented |  |
| WDC-068 | Security Options | Interactive logon: Don't display last signed-in = Enabled | CIS 2.3.7.2 | Implemented |  |
| WDC-069 | Security Options | Interactive logon: Machine inactivity limit = 300 seconds | CIS 2.3.7.3 + ISSP §4.2 | Implemented |  |
| WDC-070 | Security Options | Interactive logon: Message text = Configured | CIS 2.3.7.4 | Implemented |  |
| WDC-071 | Security Options | Interactive logon: Message title = Configured | CIS 2.3.7.5 | Implemented |  |
| WDC-072 | Security Options | Interactive logon: Smart card removal = Lock Workstation | CIS 2.3.7.9 | Implemented |  |
| WDC-073 | Security Options | MS network client: Digitally sign (always) = Enabled | CIS 2.3.8.1 | Implemented |  |
| WDC-074 | Security Options | MS network client: Send unencrypted password = Disabled | CIS 2.3.8.2 | Implemented |  |
| WDC-075 | Security Options | MS network server: Idle time before suspend = 15 min | CIS 2.3.9.1 | Implemented |  |
| WDC-076 | Security Options | MS network server: Digitally sign (always) = Enabled | CIS 2.3.9.2 | Implemented |  |
| WDC-077 | Security Options | MS network server: Disconnect when logon hours expire = Enabled | CIS 2.3.9.3 | Implemented |  |
| WDC-078 | Security Options | Network access: Allow anonymous SID/Name translation = Disabled | CIS 2.3.10.1 | Implemented |  |
| WDC-079 | Security Options | Network access: No anonymous SAM enumeration = Enabled | CIS 2.3.10.2 | Implemented |  |
| WDC-080 | Security Options | Network access: No anonymous SAM accounts and shares = Enabled | CIS 2.3.10.3 | Implemented |  |
| WDC-081 | Security Options | Network access: No password/credential storage = Enabled | CIS 2.3.10.4 | Implemented |  |
| WDC-082 | Security Options | Network access: Everyone permissions to anonymous = Disabled | CIS 2.3.10.5 | Implemented |  |
| WDC-083 | Security Options | Network access: Named Pipes anonymously (DC) = configured | CIS 2.3.10.6 | Implemented |  |
| WDC-084 | Security Options | Network access: Restrict anonymous Named Pipes and Shares = Enabled | CIS 2.3.10.10 | Implemented |  |
| WDC-085 | Security Options | Network access: Restrict clients remote calls to SAM = Administrators | CIS 2.3.10.11 | Implemented |  |
| WDC-086 | Security Options | Network access: Shares accessible anonymously = None | CIS 2.3.10.12 | Implemented |  |
| WDC-087 | Security Options | Network access: Sharing and security model = Classic | CIS 2.3.10.13 | Implemented |  |
| WDC-088 | Security Options | Network security: Allow LocalSystem NULL session fallback = Disabled | CIS 2.3.11.2 | Implemented |  |
| WDC-089 | Security Options | Network security: Allow PKU2U auth = Disabled | CIS 2.3.11.3 | Implemented |  |
| WDC-090 | Security Options | Network security: Kerberos encryption = AES128+AES256 | CIS 2.3.11.4 | Implemented |  |
| WDC-091 | Security Options | Network security: LAN Manager auth = NTLMv2, refuse LM+NTLM | CIS 2.3.11.6 | Implemented |  |
| WDC-092 | Security Options | Network security: LDAP client signing = Negotiate signing | CIS 2.3.11.8 | Implemented |  |
| WDC-093 | Security Options | Network security: Min session NTLM SSP clients = NTLMv2+128bit | CIS 2.3.11.9 | Implemented |  |
| WDC-094 | Security Options | Network security: Min session NTLM SSP servers = NTLMv2+128bit | CIS 2.3.11.10 | Implemented |  |
| WDC-095 | Security Options | Network security: Restrict NTLM: Audit Incoming = All accounts | CIS 2.3.11.11 | Implemented |  |
| WDC-096 | Security Options | Network security: Restrict NTLM: Audit in domain (DC) = All | CIS 2.3.11.12 | Implemented |  |
| WDC-097 | Security Options | Network security: Restrict NTLM: Outgoing = Audit all | CIS 2.3.11.13 | Implemented |  |
| WDC-098 | Security Options | Shutdown: Allow without logon = Disabled | CIS 2.3.13.1 | Implemented |  |
| WDC-099 | Security Options | System objects: Strengthen default permissions = Enabled | CIS 2.3.15.2 | Implemented |  |
| WDC-100 | UAC | UAC: Admin Approval Mode for built-in admin = Enabled | CIS 2.3.17.1 | Implemented |  |
| WDC-101 | UAC | UAC: Elevation prompt for admins = Consent on secure desktop | CIS 2.3.17.2 | Implemented |  |
| WDC-102 | UAC | UAC: Elevation prompt for standard users = Auto deny | CIS 2.3.17.3 | Implemented |  |
| WDC-103 | UAC | UAC: Detect app installations and prompt = Enabled | CIS 2.3.17.4 | Implemented |  |
| WDC-104 | UAC | UAC: Only elevate UIAccess in secure locations = Enabled | CIS 2.3.17.5 | Implemented |  |
| WDC-105 | UAC | UAC: Run all admins in Admin Approval Mode = Enabled | CIS 2.3.17.6 | Implemented |  |
| WDC-106 | UAC | UAC: Switch to secure desktop when prompting = Enabled | CIS 2.3.17.7 | Implemented |  |
| WDC-107 | UAC | UAC: Virtualize file/registry write failures = Enabled | CIS 2.3.17.8 | Implemented |  |
| WDC-108 | System Services | Print Spooler (DC) = Disabled and Stopped | CIS 5.1 | Implemented |  |
| WDC-109 | Firewall | Domain profile: Firewall state = On | CIS 9.1.1 | Implemented |  |
| WDC-110 | Firewall | Domain profile: Inbound = Block (default) | CIS 9.1.2 | Implemented |  |
| WDC-111 | Firewall | Domain profile: Display notification = No | CIS 9.1.3 | Implemented |  |
| WDC-112 | Firewall | Domain profile: Log size = 16384 KB | CIS 9.1.5 | Implemented |  |
| WDC-113 | Firewall | Domain profile: Log dropped packets = Yes | CIS 9.1.6 | Implemented |  |
| WDC-114 | Firewall | Domain profile: Log successful connections = Yes | CIS 9.1.7 | Implemented |  |
| WDC-115 | Firewall | Private profile: Firewall state = On | CIS 9.2.1 | Implemented |  |
| WDC-116 | Firewall | Private profile: Inbound = Block | CIS 9.2.2 | Implemented |  |
| WDC-117 | Firewall | Private profile: Log configured | CIS 9.2.4-9.2.7 | Implemented |  |
| WDC-118 | Firewall | Public profile: Firewall state = On | CIS 9.3.1 | Implemented |  |
| WDC-119 | Firewall | Public profile: Inbound = Block | CIS 9.3.2 | Implemented |  |
| WDC-120 | Firewall | Public profile: Apply local firewall rules = No | CIS 9.3.4 | Implemented |  |
| WDC-121 | Firewall | Public profile: Apply local connection security rules = No | CIS 9.3.5 | Implemented |  |
| WDC-122 | Firewall | Public profile: Log configured | CIS 9.3.6-9.3.9 | Implemented |  |
| WDC-123 | Audit Policy | Audit Credential Validation = Success+Failure | CIS 17.1.1 | Implemented |  |
| WDC-124 | Audit Policy | Audit Kerberos Authentication Service (DC) = Success+Failure | CIS 17.1.2 | Implemented |  |
| WDC-125 | Audit Policy | Audit Kerberos Service Ticket Operations (DC) = Success+Failure | CIS 17.1.3 | Implemented |  |
| WDC-126 | Audit Policy | Audit Application Group Management = Success+Failure | CIS 17.2.1 | Implemented |  |
| WDC-127 | Audit Policy | Audit Computer Account Management (DC) = Success | CIS 17.2.2 | Implemented |  |
| WDC-128 | Audit Policy | Audit Distribution Group Management (DC) = Success | CIS 17.2.3 | Implemented |  |
| WDC-129 | Audit Policy | Audit Other Account Management Events (DC) = Success | CIS 17.2.4 | Implemented |  |
| WDC-130 | Audit Policy | Audit Security Group Management = Success | CIS 17.2.5 | Implemented |  |
| WDC-131 | Audit Policy | Audit User Account Management = Success+Failure | CIS 17.2.6 | Implemented |  |
| WDC-132 | Audit Policy | Audit PNP Activity = Success | CIS 17.3.1 | Implemented |  |
| WDC-133 | Audit Policy | Audit Process Creation = Success | CIS 17.3.2 | Implemented |  |
| WDC-134 | Audit Policy | Audit Directory Service Access (DC) = Failure | CIS 17.4.1 | Implemented |  |
| WDC-135 | Audit Policy | Audit Directory Service Changes (DC) = Success | CIS 17.4.2 | Implemented |  |
| WDC-136 | Audit Policy | Audit Account Lockout = Failure | CIS 17.5.1 | Implemented |  |
| WDC-137 | Audit Policy | Audit Group Membership = Success | CIS 17.5.2 | Implemented |  |
| WDC-138 | Audit Policy | Audit Logoff = Success | CIS 17.5.3 | Implemented |  |
| WDC-139 | Audit Policy | Audit Logon = Success+Failure | CIS 17.5.4 | Implemented |  |
| WDC-140 | Audit Policy | Audit Other Logon/Logoff Events = Success+Failure | CIS 17.5.5 | Implemented |  |
| WDC-141 | Audit Policy | Audit Special Logon = Success | CIS 17.5.6 | Implemented |  |
| WDC-142 | Audit Policy | Audit Detailed File Share = Failure | CIS 17.6.1 | Implemented |  |
| WDC-143 | Audit Policy | Audit File Share = Success+Failure | CIS 17.6.2 | Implemented |  |
| WDC-144 | Audit Policy | Audit Other Object Access Events = Success+Failure | CIS 17.6.3 | Implemented |  |
| WDC-145 | Audit Policy | Audit Removable Storage = Success+Failure | CIS 17.6.4 | Implemented |  |
| WDC-146 | Audit Policy | Audit Audit Policy Change = Success | CIS 17.7.1 | Implemented |  |
| WDC-147 | Audit Policy | Audit Authentication Policy Change = Success | CIS 17.7.2 | Implemented |  |
| WDC-148 | Audit Policy | Audit Authorization Policy Change = Success | CIS 17.7.3 | Implemented |  |
| WDC-149 | Audit Policy | Audit MPSSVC Rule-Level Policy Change = Success+Failure | CIS 17.7.4 | Implemented |  |
| WDC-150 | Audit Policy | Audit Other Policy Change Events = Failure | CIS 17.7.5 | Implemented |  |
| WDC-151 | Audit Policy | Audit Sensitive Privilege Use = Success+Failure | CIS 17.8.1 | Implemented |  |
| WDC-152 | Audit Policy | Audit IPsec Driver = Success+Failure | CIS 17.9.1 | Implemented |  |
| WDC-153 | Audit Policy | Audit Other System Events = Success+Failure | CIS 17.9.2 | Implemented |  |
| WDC-154 | Audit Policy | Audit Security State Change = Success | CIS 17.9.3 | Implemented |  |
| WDC-155 | Audit Policy | Audit Security System Extension = Success | CIS 17.9.4 | Implemented |  |
| WDC-156 | Audit Policy | Audit System Integrity = Success+Failure | CIS 17.9.5 | Implemented |  |
| WDC-157 | Admin Templates | Prevent lock screen camera = Enabled | CIS 18.1.1.1 | Implemented |  |
| WDC-158 | Admin Templates | Prevent lock screen slide show = Enabled | CIS 18.1.1.2 | Implemented |  |
| WDC-159 | Admin Templates | Allow online speech recognition = Disabled | CIS 18.1.2.2 | Implemented |  |
| WDC-160 | Admin Templates | Allow Online Tips = Disabled | CIS 18.1.3 | Implemented |  |
| WDC-161 | Admin Templates | LAPS: Configure password backup to AD = Enabled | CIS 18.9.26.1 | Implemented |  |
| WDC-162 | Admin Templates | LAPS: No expiration > policy = Enabled | CIS 18.9.26.2 | Implemented |  |
| WDC-163 | Admin Templates | LAPS: Enable password encryption = Enabled | CIS 18.9.26.3 | Implemented |  |
| WDC-164 | Admin Templates | LAPS: Password complexity = Large+Small+Num+Special | CIS 18.9.26.4 | Implemented |  |
| WDC-165 | Admin Templates | LAPS: Password length = 15+ | CIS 18.9.26.5 | Implemented |  |
| WDC-166 | Admin Templates | LAPS: Password age = 30 days | CIS 18.9.26.6 | Implemented |  |
| WDC-167 | Admin Templates | LAPS: Post-auth grace period = 8h | CIS 18.9.26.7 | Implemented |  |
| WDC-168 | Admin Templates | LAPS: Post-auth actions = Reset+Logoff | CIS 18.9.26.8 | Implemented |  |
| WDC-169 | Admin Templates | MS Security Guide: UAC restrictions local accounts = Enabled | CIS 18.4.1 | Implemented |  |
| WDC-170 | Admin Templates | MS Security Guide: SMBv1 client = Disabled | CIS 18.4.2 | Implemented |  |
| WDC-171 | Admin Templates | MS Security Guide: SMBv1 server = Disabled | CIS 18.4.3 | Implemented |  |
| WDC-172 | Admin Templates | MS Security Guide: Certificate Padding = Enabled | CIS 18.4.4 | Implemented |  |
| WDC-173 | Admin Templates | MS Security Guide: SEHOP = Enabled | CIS 18.4.5 | Implemented |  |
| WDC-174 | Admin Templates | MS Security Guide: NetBT NodeType = P-node | CIS 18.4.6 | Implemented |  |
| WDC-175 | Admin Templates | MSS: AutoAdminLogon = Disabled | CIS 18.5.1 | Implemented |  |
| WDC-176 | Admin Templates | MSS: DisableIPSourceRouting IPv6 = Highest protection | CIS 18.5.2 | Implemented |  |
| WDC-177 | Admin Templates | MSS: DisableIPSourceRouting IPv4 = Highest protection | CIS 18.5.3 | Implemented |  |
| WDC-178 | Admin Templates | MSS: EnableICMPRedirect = Disabled | CIS 18.5.4 | Implemented |  |
| WDC-179 | Admin Templates | MSS: KeepAliveTime = 300000ms | CIS 18.5.5 | Implemented |  |
| WDC-180 | Admin Templates | MSS: NoNameReleaseOnDemand = Enabled | CIS 18.5.6 | Implemented |  |
| WDC-181 | Admin Templates | MSS: PerformRouterDiscovery = Disabled | CIS 18.5.7 | Implemented |  |
| WDC-182 | Admin Templates | MSS: SafeDllSearchMode = Enabled | CIS 18.5.8 | Implemented |  |
| WDC-183 | Admin Templates | MSS: TcpMaxDataRetransmissions IPv6 = 3 | CIS 18.5.9 | Implemented |  |
| WDC-184 | Admin Templates | MSS: TcpMaxDataRetransmissions IPv4 = 3 | CIS 18.5.10 | Implemented |  |
| WDC-185 | Admin Templates | MSS: WarningLevel = 90% | CIS 18.5.11 | Implemented |  |
| WDC-186 | Admin Templates | DNS: Configure mDNS = Disabled | CIS 18.6.4.1 | Implemented |  |
| WDC-187 | Admin Templates | DNS: NetBIOS = Disable on public networks | CIS 18.6.4.2 | Implemented |  |
| WDC-188 | Admin Templates | DNS: Turn off default IPv6 DNS servers = Enabled | CIS 18.6.4.3 | Implemented |  |
| WDC-189 | Admin Templates | DNS: Turn off multicast name resolution = Enabled | CIS 18.6.4.4 | Implemented |  |
| WDC-190 | Admin Templates | Fonts: Enable Font Providers = Disabled | CIS 18.6.5.1 | Implemented |  |
| WDC-191 | Admin Templates | LanMan Server: Audit client encryption/signing = Enabled | CIS 18.6.7.1-7.3 | Implemented |  |
| WDC-192 | Admin Templates | LanMan Server: Enable authentication rate limiter = Enabled | CIS 18.6.7.4 | Implemented |  |
| WDC-193 | Admin Templates | LanMan Server: Disable remote mailslots = Enabled | CIS 18.6.7.5 | Implemented |  |
| WDC-194 | Admin Templates | LanMan Server: Mandate min SMB version 3.1.1 | CIS 18.6.7.6 | Implemented |  |
| WDC-195 | Admin Templates | LanMan Workstation: Require Encryption = Enabled | CIS 18.6.8.7 | Implemented |  |
| WDC-196 | Admin Templates | LLTDIO driver = Disabled | CIS 18.6.9.1 | Implemented |  |
| WDC-197 | Admin Templates | RSPNDR driver = Disabled | CIS 18.6.9.2 | Implemented |  |
| WDC-198 | Admin Templates | Turn off MS Peer-to-Peer Networking = Enabled | CIS 18.6.10.2 | Implemented |  |
| WDC-199 | Admin Templates | Prohibit Network Bridge = Enabled | CIS 18.6.11.2 | Implemented |  |
| WDC-200 | Admin Templates | Prohibit Internet Connection Sharing = Enabled | CIS 18.6.11.3 | Implemented |  |
| WDC-201 | Admin Templates | Require domain users elevate for network location = Enabled | CIS 18.6.11.4 | Implemented |  |
| WDC-202 | Admin Templates | Hardened UNC Paths (NETLOGON+SYSVOL) = Mutual Auth+Integrity+Privacy | CIS 18.6.14.1 | Implemented |  |
| WDC-203 | Admin Templates | Disable IPv6 = 0xff (all disabled) | CIS 18.6.19.2.1 | Implemented |  |
| WDC-204 | Admin Templates | Minimize simultaneous connections = 3 (no Wi-Fi on Ethernet) | CIS 18.6.21.1 | Implemented |  |
| WDC-205 | Admin Templates | Allow Print Spooler accept client connections = Disabled | CIS 18.7.1 | Implemented |  |
| WDC-206 | Admin Templates | Configure Redirection Guard = Enabled | CIS 18.7.2 | Implemented |  |
| WDC-207 | Admin Templates | RPC outgoing: Protocol = RPC over TCP | CIS 18.7.3 | Implemented |  |
| WDC-208 | Admin Templates | RPC outgoing: Use authentication = Default | CIS 18.7.4 | Implemented |  |
| WDC-209 | Admin Templates | RPC listener: Protocols = RPC over TCP | CIS 18.7.5 | Implemented |  |
| WDC-210 | Admin Templates | RPC listener: Auth = Negotiate or higher | CIS 18.7.6 | Implemented |  |
| WDC-211 | Admin Templates | RPC over TCP port = 0 | CIS 18.7.7 | Implemented |  |
| WDC-212 | Admin Templates | RPC packet level privacy = Enabled | CIS 18.7.8 | Implemented |  |
| WDC-213 | Admin Templates | Windows protected print = Enabled | CIS 18.7.9 | Implemented |  |
| WDC-214 | Admin Templates | Limit print driver install to Admins = Enabled | CIS 18.7.10 | Implemented |  |
| WDC-215 | Admin Templates | Turn off notifications network usage = Enabled | CIS 18.8.1.1 | Implemented |  |
| WDC-216 | Admin Templates | Include command line in process creation = Enabled | CIS 18.9.3.1 | Implemented |  |
| WDC-217 | Admin Templates | Encryption Oracle Remediation = Force Updated Clients | CIS 18.9.4.1 | Implemented |  |
| WDC-218 | Admin Templates | Remote host: delegate non-exportable credentials = Enabled | CIS 18.9.4.2 | Implemented |  |
| WDC-219 | Admin Templates | VBS: Turn On = Enabled | CIS 18.9.5.1 | Implemented |  |
| WDC-220 | Admin Templates | VBS: Platform Security Level = Secure Boot | CIS 18.9.5.2 | Implemented |  |
| WDC-221 | Admin Templates | VBS: HVCI = Enabled with UEFI lock | CIS 18.9.5.3 | Implemented |  |
| WDC-222 | Admin Templates | VBS: Require UEFI Memory Attributes Table = True | CIS 18.9.5.4 | Implemented |  |
| WDC-223 | Admin Templates | VBS: Credential Guard (DC only) = Disabled | CIS 18.9.5.6 | Implemented | DC must have this DISABLED per CIS |
| WDC-224 | Admin Templates | VBS: Secure Launch = Enabled | CIS 18.9.5.7 | Implemented |  |
| WDC-225 | Admin Templates | Kernel DMA Protection: Block All | CIS 18.9.24.1 | Implemented |  |
| WDC-226 | Admin Templates | Prevent auto download of apps with device metadata | CIS 18.9.7.1.1 | Implemented |  |
| WDC-227 | Admin Templates | Boot-Start Driver: Good+Unknown+Bad but critical | CIS 18.9.13.1 | Implemented |  |
| WDC-228 | Admin Templates | LSASS: Allow Custom SSPs/APs (DC) = Disabled | CIS 18.9.27.1 | Implemented |  |
| WDC-229 | Admin Templates | LSASS: Run as protected process = Enabled with UEFI Lock | CIS 18.9.27.2 | Implemented |  |
| WDC-230 | Admin Templates | Security policy processing: No apply during periodic background = FALSE | CIS 18.9.19.2 | Implemented |  |
| WDC-231 | Admin Templates | Security policy processing: Process even if unchanged = TRUE | CIS 18.9.19.3 | Implemented |  |
| WDC-232 | Admin Templates | Turn off background refresh of Group Policy = Disabled | CIS 18.9.19.5 | Implemented |  |
| WDC-233 | Admin Templates | Turn off downloading print drivers over HTTP = Enabled | CIS 18.9.20.1.1 | Implemented |  |
| WDC-234 | Admin Templates | Turn off Internet Connection Wizard = Enabled | CIS 18.9.20.1.4 | Implemented |  |
| WDC-235 | Admin Templates | Turn off Internet download for Web publishing = Enabled | CIS 18.9.20.1.5 | Implemented |  |
| WDC-236 | Admin Templates | Turn off printing over HTTP = Enabled | CIS 18.9.20.1.6 | Implemented |  |
| WDC-237 | Admin Templates | Turn off Registration if URL = Enabled | CIS 18.9.20.1.7 | Implemented |  |
| WDC-238 | Admin Templates | Turn off Search Companion updates = Enabled | CIS 18.9.20.1.8 | Implemented |  |
| WDC-239 | Admin Templates | Turn off Windows Messenger CEIP = Enabled | CIS 18.9.20.1.11 | Implemented |  |
| WDC-240 | Admin Templates | Turn off Windows CEIP = Enabled | CIS 18.9.20.1.12 | Implemented |  |
| WDC-241 | Admin Templates | Turn off Windows Error Reporting = Enabled | CIS 18.9.20.1.13 | Implemented |  |
| WDC-242 | Admin Templates | Kerberos: Support device auth = Automatic | CIS 18.9.23.1 | Implemented |  |
| WDC-243 | Admin Templates | SAM: ROCA-vulnerable WHfB keys (DC) = Block | CIS 18.9.41.1 | Implemented |  |
| WDC-244 | Admin Templates | SAM: Strong encryption change password (DC) = Allow strong only | CIS 18.9.41.2 | Implemented |  |
| WDC-245 | Admin Templates | Block user from showing account details at sign-in = Enabled | CIS 18.9.29.1 | Implemented |  |
| WDC-246 | Admin Templates | Do not display network selection UI = Enabled | CIS 18.9.29.2 | Implemented |  |
| WDC-247 | Admin Templates | Do not enumerate connected users on domain-joined = Enabled | CIS 18.9.29.3 | Implemented |  |
| WDC-248 | Admin Templates | Turn off app notifications on lock screen = Enabled | CIS 18.9.29.5 | Implemented |  |
| WDC-249 | Admin Templates | Turn off convenience PIN sign-in = Disabled | CIS 18.9.29.6 | Implemented |  |
| WDC-250 | Admin Templates | Block NetBIOS-based DC location = Enabled | CIS 18.9.31.1.1 | Implemented |  |
| WDC-251 | Admin Templates | Allow Clipboard synchronization = Disabled | CIS 18.9.33.1 | Implemented |  |
| WDC-252 | Admin Templates | Allow upload of User Activities = Disabled | CIS 18.9.33.2 | Implemented |  |
| WDC-253 | Admin Templates | Disallow AutoPlay for non-volume devices = Enabled | CIS 18.10.8.1 | Implemented |  |
| WDC-254 | Admin Templates | Default AutoRun = Do not execute | CIS 18.10.8.2 | Implemented |  |
| WDC-255 | Admin Templates | Turn off AutoPlay = All drives | CIS 18.10.8.3 | Implemented |  |
| WDC-256 | Admin Templates | Configure enhanced anti-spoofing = Enabled | CIS 18.10.9.1.1 | Implemented |  |
| WDC-257 | Admin Templates | Turn off cloud consumer account state content = Enabled | CIS 18.10.13.1 | Implemented |  |
| WDC-258 | Admin Templates | Turn off cloud optimized content = Enabled | CIS 18.10.13.2 | Implemented |  |
| WDC-259 | Admin Templates | Allow Diagnostic Data = Required only | CIS 18.10.16.1 | Implemented |  |
| WDC-260 | Admin Templates | Disable Authenticated Proxy for Connected User Experience = Enabled | CIS 18.10.16.2 | Implemented |  |
| WDC-261 | Admin Templates | Do not show feedback notifications = Enabled | CIS 18.10.16.3 | Implemented |  |
| WDC-262 | Admin Templates | Enable OneSettings Auditing = Enabled | CIS 18.10.16.4 | Implemented |  |
| WDC-263 | Admin Templates | Limit Diagnostic Log Collection = Enabled | CIS 18.10.16.5 | Implemented |  |
| WDC-264 | Admin Templates | Limit Dump Collection = Enabled | CIS 18.10.16.6 | Implemented |  |
| WDC-265 | Admin Templates | App Event Log max size = 32768 KB | CIS 18.10.26.1.2 | Implemented |  |
| WDC-266 | Admin Templates | Security Event Log max size = 196608 KB | CIS 18.10.26.2.2 | Implemented |  |
| WDC-267 | Admin Templates | Setup Event Log max size = 32768 KB | CIS 18.10.26.3.2 | Implemented |  |
| WDC-268 | Admin Templates | System Event Log max size = 32768 KB | CIS 18.10.26.4.2 | Implemented |  |
| WDC-269 | Admin Templates | Turn off heap termination on corruption = Disabled | CIS 18.10.29.4 | Implemented |  |
| WDC-270 | Admin Templates | Turn off shell protocol protected mode = Disabled | CIS 18.10.29.5 | Implemented |  |
| WDC-271 | Admin Templates | Allow Use of Camera = Disabled | CIS 18.10.11.1 | Implemented |  |
| WDC-272 | Admin Templates | Block all consumer Microsoft account auth = Enabled | CIS 18.10.41.1 | Implemented |  |
| WDC-273 | Admin Templates | Enable EDR in block mode = Enabled | CIS 18.10.42.4.1 | Implemented |  |
| WDC-274 | Admin Templates | Local override for MAPS reporting = Disabled | CIS 18.10.42.5.1 | Implemented |  |
| WDC-275 | Admin Templates | Join Microsoft MAPS = Advanced | CIS 18.10.42.5.2 | Implemented |  |
| WDC-276 | Admin Templates | Configure ASR rules = Enabled | CIS 18.10.42.6.1.1 | Implemented |  |
| WDC-277 | Admin Templates | Configure ASR rules state | CIS 18.10.42.6.1.2 | Implemented |  |
| WDC-278 | Admin Templates | Prevent users/apps accessing dangerous websites = Block | CIS 18.10.42.6.3.1 | Implemented |  |
| WDC-279 | Admin Templates | Real-time protection during OOBE = Enabled | CIS 18.10.42.10.1 | Implemented |  |
| WDC-280 | Admin Templates | Scan downloaded files = Enabled | CIS 18.10.42.10.2 | Implemented |  |
| WDC-281 | Admin Templates | Turn off real-time protection = Disabled | CIS 18.10.42.10.3 | Implemented |  |
| WDC-282 | Admin Templates | Turn on behavior monitoring = Enabled | CIS 18.10.42.10.4 | Implemented |  |
| WDC-283 | Admin Templates | Turn on script scanning = Enabled | CIS 18.10.42.10.5 | Implemented |  |
| WDC-284 | Admin Templates | Brute-Force Protection aggressiveness = Medium+ | CIS 18.10.42.11.1.1 | Implemented |  |
| WDC-285 | Admin Templates | Remote Encryption Protection Mode = Audit+ | CIS 18.10.42.11.1.2 | Implemented |  |
| WDC-286 | Admin Templates | Configure Watson events = Disabled | CIS 18.10.42.12.1 | Implemented |  |
| WDC-287 | Admin Templates | Scan packed executables = Enabled | CIS 18.10.42.13.2 | Implemented |  |
| WDC-288 | Admin Templates | Scan removable drives = Enabled | CIS 18.10.42.13.3 | Implemented |  |
| WDC-289 | Admin Templates | Trigger quick scan after 7 days without scan | CIS 18.10.42.13.4 | Implemented |  |
| WDC-290 | Admin Templates | Turn on email scanning = Enabled | CIS 18.10.42.13.5 | Implemented |  |
| WDC-291 | Admin Templates | Configure detection for PUAs = Block | CIS 18.10.42.16 | Implemented |  |
| WDC-292 | Admin Templates | Control exclusions visible to local users = Enabled | CIS 18.10.42.17 | Implemented |  |
| WDC-293 | Admin Templates | Allow Offer Remote Assistance = Disabled | CIS 18.9.37.1 | Implemented |  |
| WDC-294 | Admin Templates | Allow Solicited Remote Assistance = Disabled | CIS 18.9.37.2 | Implemented |  |
| WDC-295 | Admin Templates | Do not allow COM port redirection = Enabled | CIS 18.10.57.3.3.2 | Implemented |  |
| WDC-296 | Admin Templates | Do not allow drive redirection = Enabled | CIS 18.10.57.3.3.3 | Implemented |  |
| WDC-297 | Admin Templates | Do not allow location redirection = Enabled | CIS 18.10.57.3.3.4 | Implemented |  |
| WDC-298 | Admin Templates | Do not allow LPT port redirection = Enabled | CIS 18.10.57.3.3.5 | Implemented |  |
| WDC-299 | Admin Templates | Do not allow supported PnP device redirection = Enabled | CIS 18.10.57.3.3.6 | Implemented |  |
| WDC-300 | Admin Templates | Do not allow WebAuthn redirection = Enabled | CIS 18.10.57.3.3.7 | Implemented |  |
| WDC-301 | Admin Templates | Restrict clipboard transfer from server to client = Enabled | CIS 18.10.57.3.3.8 | Implemented |  |
| WDC-302 | Admin Templates | Always prompt for password on RDS connection = Enabled | CIS 18.10.57.3.9.1 | Implemented |  |
| WDC-303 | Admin Templates | Require secure RPC communication = Enabled | CIS 18.10.57.3.9.2 | Implemented |  |
| WDC-304 | Admin Templates | Require SSL for RDP = SSL | CIS 18.10.57.3.9.3 | Implemented |  |
| WDC-305 | Admin Templates | Require NLA for remote connections = Enabled | CIS 18.10.57.3.9.4 | Implemented |  |
| WDC-306 | Admin Templates | Set client connection encryption = High Level | CIS 18.10.57.3.9.5 | Implemented |  |
| WDC-307 | Admin Templates | Set time limit: active idle RDS = 15 min | CIS 18.10.57.3.10.1 | Implemented |  |
| WDC-308 | Admin Templates | Set time limit: disconnected sessions = 1 min | CIS 18.10.57.3.10.2 | Implemented |  |
| WDC-309 | Admin Templates | Prevent downloading of enclosures = Enabled | CIS 18.10.58.1 | Implemented |  |
| WDC-310 | Admin Templates | Allow Cloud Search = Disable Cloud Search | CIS 18.10.59.2 | Implemented |  |
| WDC-311 | Admin Templates | Allow indexing of encrypted files = Disabled | CIS 18.10.59.3 | Implemented |  |
| WDC-312 | Admin Templates | Turn off KMS Client Online AVS Validation = Enabled | CIS 18.10.63.1 | Implemented |  |
| WDC-313 | Admin Templates | PowerShell: Script Block Logging = Enabled | CIS 18.10.88.1 | Implemented |  |
| WDC-314 | Admin Templates | PowerShell: Transcription = Enabled | CIS 18.10.88.2 | Implemented |  |
| WDC-315 | Admin Templates | WinRM Client: Allow Basic auth = Disabled | CIS 18.10.90.1.1 | Implemented |  |
| WDC-316 | Admin Templates | WinRM Client: Allow unencrypted traffic = Disabled | CIS 18.10.90.1.2 | Implemented |  |
| WDC-317 | Admin Templates | WinRM Client: Disallow Digest auth = Enabled | CIS 18.10.90.1.3 | Implemented |  |
| WDC-318 | Admin Templates | WinRM Service: Allow Basic auth = Disabled | CIS 18.10.90.2.1 | Implemented |  |
| WDC-319 | Admin Templates | WinRM Service: Allow remote server management = Disabled | CIS 18.10.90.2.2 | Implemented |  |
| WDC-320 | Admin Templates | WinRM Service: Allow unencrypted traffic = Disabled | CIS 18.10.90.2.3 | Implemented |  |
| WDC-321 | Admin Templates | WinRM Service: Disallow RunAs credentials = Enabled | CIS 18.10.90.2.4 | Implemented |  |
| WDC-322 | Admin Templates | Windows Remote Shell: Allow Remote Shell Access = Disabled | CIS 18.10.91.1 | Implemented |  |
| WDC-323 | Admin Templates | Windows Security: Prevent users modifying settings = Enabled | CIS 18.10.93.2.1 | Implemented |  |
| WDC-324 | Admin Templates | Windows Update: No auto-restart = Disabled | CIS 18.10.94.1.1 | Implemented |  |
| WDC-325 | Admin Templates | Windows Update: Configure Automatic Updates = Enabled | CIS 18.10.94.2.1 | Implemented |  |
| WDC-326 | Admin Templates | Windows Update: Scheduled install day = 0 (every day) | CIS 18.10.94.2.2 | Implemented |  |
| WDC-327 | Admin Templates | Disable WPAD = Enabled | CIS 18.11.1 | Implemented |  |
| WDC-328 | Admin Templates | Disable proxy auth over loopback = Enabled | CIS 18.11.2 | Implemented |  |
| WDC-329 | Admin Templates | Allow Windows Ink Workspace = Disabled | CIS 18.10.81.2 | Implemented |  |
| WDC-330 | Admin Templates | Allow user control over installs = Disabled | CIS 18.10.82.1 | Implemented |  |
| WDC-331 | Admin Templates | Always install with elevated privileges = Disabled | CIS 18.10.82.2 | Implemented |  |
| WDC-332 | Admin Templates | Prevent MPR password notifications = Disabled | CIS 18.10.83.1 | Implemented |  |
| WDC-333 | Admin Templates | Sign-in and lock last user after restart = Disabled | CIS 18.10.83.2 | Implemented |  |
| WDC-334 | Admin Templates | Allow Microsoft accounts to be optional = Enabled | CIS 18.10.6.1 | Implemented |  |
| WDC-335 | Admin Templates | Windows Defender SmartScreen = Enabled: Warn and prevent bypass | CIS 18.10.77.2.1 | Implemented |  |
| WDC-336 | Admin Templates | Turn off location = Enabled | CIS 18.10.36.1 | Implemented |  |
| WDC-337 | Admin Templates | Allow Message Service Cloud Sync = Disabled | CIS 18.10.40.1 | Implemented |  |
| WDC-338 | Admin Templates | Turn off Push To Install = Enabled | CIS 18.10.56.1 | Implemented |  |
| WDC-339 | Admin Templates | Prevent Codec Download = Enabled | CIS 19.7.46.2.1 | Implemented |  |
| WDC-340 | Admin Templates | Disallow copying user input methods for sign-in = Enabled | CIS 18.9.28.1 | Implemented |  |
| WDC-341 | ISSP | Fine-grained PSO: Standard users min 12 chars, 90-day expiry | ISSP §7.1 | Implemented |  |
| WDC-342 | ISSP | Fine-grained PSO: Admin accounts min 18 chars, 60-day expiry | ISSP §7.2 | Implemented |  |
| WDC-343 | ISSP | Session auto-lock after 300 seconds (5 min) | ISSP §4.2 | Implemented | Via WDC-069 |
| WDC-344 | ISSP | Emergency local admin (breakglass) account | ISSP §8 | Not Implemented | Procedural: passwords must be printed, sealed in envelopes, stored in physical safe. Cannot be automated. |
| WDC-345 | ISSP | Account deactivation on departure (disable 90 days, delete day 91) | ISSP §6 | Not Implemented | HR lifecycle process requiring integration with HR system. Cannot be automated without IAM/ITSM. |
| WDC-346 | ISSP | CMDB asset inventory maintenance | ISSP §4 | Not Implemented | Organizational process — requires ongoing manual updates. Script generates a point-in-time snapshot only. |
| WDC-347 | ISSP | VPN enforcement for remote access | ISSP §4.2 | Not Implemented | Requires VPN gateway infrastructure configuration — out of scope for OS hardening script. |
| WDC-348 | ISSP | BitLocker full disk encryption for laptops | ISSP §5.1 | Implemented |  |
| WDC-349 | ISSP | Centralized antivirus management | ISSP §5.1 | Not Implemented | Requires SCCM/Intune/AV management server. Script enables Windows Defender with hardened settings only. |
| WDC-350 | ISSP | Offsite backup procedure | ISSP §10 | Not Implemented | Requires backup infrastructure. Script documents the requirement and checks backup service status. |
| WDC-351 | ISSP | Separate admin accounts from user accounts | ISSP §6 | Not Implemented | Organizational naming convention. Script validates and reports but cannot enforce account restructuring. |


---

## Ubuntu Client Hardening (CIS Ubuntu + ISSP)

| ID | Category | Hardening Point | Source | Status | Reason if Not Implemented |
|----|----------|-----------------|--------|--------|---------------------------|
| UBU-001 | Firewall | Install and enable UFW | CIS | Implemented |  |
| UBU-002 | Firewall | UFW default deny incoming | CIS | Implemented |  |
| UBU-003 | Firewall | UFW default allow outgoing | CIS | Implemented |  |
| UBU-004 | Firewall | UFW allow SSH (22/tcp) | CIS | Implemented |  |
| UBU-005 | Kernel | sysctl: net.ipv4.ip_forward = 0 | CIS | Implemented |  |
| UBU-006 | Kernel | sysctl: net.ipv4.conf.all.send_redirects = 0 | CIS | Implemented |  |
| UBU-007 | Kernel | sysctl: net.ipv4.conf.all.accept_redirects = 0 | CIS | Implemented |  |
| UBU-008 | Kernel | sysctl: net.ipv4.conf.default.accept_redirects = 0 | CIS | Implemented |  |
| UBU-009 | Kernel | sysctl: net.ipv4.conf.all.secure_redirects = 0 | CIS | Implemented |  |
| UBU-010 | Kernel | sysctl: net.ipv4.conf.default.secure_redirects = 0 | CIS | Implemented |  |
| UBU-011 | Kernel | sysctl: net.ipv4.conf.all.log_martians = 1 | CIS | Implemented |  |
| UBU-012 | Kernel | sysctl: net.ipv4.tcp_syncookies = 1 | CIS | Implemented |  |
| UBU-013 | Kernel | sysctl: net.ipv4.icmp_echo_ignore_broadcasts = 1 | CIS | Implemented |  |
| UBU-014 | Kernel | sysctl: net.ipv4.icmp_ignore_bogus_error_responses = 1 | CIS | Implemented |  |
| UBU-015 | Kernel | sysctl: net.ipv4.conf.all.rp_filter = 1 | CIS | Implemented |  |
| UBU-016 | Kernel | sysctl: net.ipv6.conf.all.disable_ipv6 = 1 | CIS | Implemented |  |
| UBU-017 | Kernel | sysctl: kernel.randomize_va_space = 2 (ASLR) | CIS | Implemented |  |
| UBU-018 | Kernel | sysctl: kernel.dmesg_restrict = 1 | CIS | Implemented |  |
| UBU-019 | Kernel | sysctl: kernel.perf_event_paranoid = 3 | CIS | Implemented |  |
| UBU-020 | Kernel | sysctl: fs.suid_dumpable = 0 | CIS | Implemented |  |
| UBU-021 | Kernel | sysctl: net.ipv4.conf.all.accept_source_route = 0 | CIS | Implemented |  |
| UBU-022 | AppArmor | Enable AppArmor in enforce mode | CIS | Implemented |  |
| UBU-023 | AppArmor | Ensure all AppArmor profiles loaded | CIS | Implemented |  |
| UBU-024 | SSH | PermitRootLogin = no | CIS | Implemented |  |
| UBU-025 | SSH | Protocol = 2 (implied in modern sshd) | CIS | Implemented |  |
| UBU-026 | SSH | MaxAuthTries = 3 | CIS | Implemented |  |
| UBU-027 | SSH | PermitEmptyPasswords = no | CIS | Implemented |  |
| UBU-028 | SSH | X11Forwarding = no | CIS | Implemented |  |
| UBU-029 | SSH | ClientAliveInterval = 300 (5 min timeout - ISSP) | CIS + ISSP §4.2 | Implemented |  |
| UBU-030 | SSH | ClientAliveCountMax = 0 | CIS | Implemented |  |
| UBU-031 | SSH | LoginGraceTime = 60 | CIS | Implemented |  |
| UBU-032 | SSH | Banner configured with legal warning | CIS + ISSP | Implemented |  |
| UBU-033 | SSH | Ciphers = chacha20-poly1305, aes256-gcm, aes128-gcm | CIS | Implemented |  |
| UBU-034 | SSH | MACs = hmac-sha2-512-etm, hmac-sha2-256-etm | CIS | Implemented |  |
| UBU-035 | SSH | KexAlgorithms = curve25519-sha256, diffie-hellman-group14-sha256+ | CIS | Implemented |  |
| UBU-036 | SSH | PasswordAuthentication = yes (key-only not forced) | CIS | Not Implemented | Disabling password auth requires SSH keys pre-configured. Would lock out admins without prior key setup. |
| UBU-037 | SSH | AllowGroups/AllowUsers restriction | CIS | Not Implemented | Site-specific: requires knowledge of local user/group structure. Documented as recommended manual step. |
| UBU-038 | PAM | pwquality: minlen=12, dcredit=-1, ucredit=-1, lcredit=-1, ocredit=-1 | CIS + ISSP §7.1 | Implemented |  |
| UBU-039 | PAM | pwquality: maxrepeat = 3 | CIS | Implemented |  |
| UBU-040 | PAM | Password history = 24 (pam_pwhistory) | CIS | Implemented |  |
| UBU-041 | PAM | Account lockout after 5 failures (pam_faillock) | CIS | Implemented |  |
| UBU-042 | PAM | Lockout duration = 15 min | CIS | Implemented |  |
| UBU-043 | PAM | Unlock after 15 min (fail_interval = 900) | CIS | Implemented |  |
| UBU-044 | Login Defs | PASS_MAX_DAYS = 90 | CIS + ISSP §7.1 | Implemented |  |
| UBU-045 | Login Defs | PASS_MIN_DAYS = 1 | CIS | Implemented |  |
| UBU-046 | Login Defs | PASS_WARN_AGE = 14 | CIS | Implemented |  |
| UBU-047 | Login Defs | PASS_MIN_LEN = 12 | ISSP §7.1 | Implemented |  |
| UBU-048 | Services | Disable telnet | CIS | Implemented |  |
| UBU-049 | Services | Disable ftp (vsftpd) | CIS | Implemented |  |
| UBU-050 | Services | Disable rsh, rlogin, rexec | CIS | Implemented |  |
| UBU-051 | Services | Disable avahi-daemon | CIS | Implemented |  |
| UBU-052 | Services | Disable cups (if not print server) | CIS | Implemented |  |
| UBU-053 | Services | Disable isc-dhcp-server | CIS | Implemented |  |
| UBU-054 | Services | Disable slapd (LDAP server) | CIS | Implemented |  |
| UBU-055 | Services | Disable nfs-server | CIS | Implemented |  |
| UBU-056 | Services | Disable rpcbind | CIS | Implemented |  |
| UBU-057 | Services | Disable named (DNS server) | CIS | Implemented |  |
| UBU-058 | Services | Disable apache2 | CIS | Implemented |  |
| UBU-059 | Services | Disable dovecot | CIS | Implemented |  |
| UBU-060 | Services | Disable smbd/nmbd | CIS | Not Implemented | May be required for Active Directory domain join (Samba/winbind). Skipped to preserve AD connectivity. |
| UBU-061 | Auditd | Install and enable auditd | CIS | Implemented |  |
| UBU-062 | Auditd | Audit: time change events | CIS | Implemented |  |
| UBU-063 | Auditd | Audit: user/group modification | CIS | Implemented |  |
| UBU-064 | Auditd | Audit: network configuration changes | CIS | Implemented |  |
| UBU-065 | Auditd | Audit: sudo usage | CIS | Implemented |  |
| UBU-066 | Auditd | Audit: file deletions by users | CIS | Implemented |  |
| UBU-067 | Auditd | Audit: system call rules (setuid, mount) | CIS | Implemented |  |
| UBU-068 | Auditd | Audit: login/logout events (wtmp, btmp, lastlog) | CIS | Implemented |  |
| UBU-069 | Auditd | Audit: privileged commands | CIS | Implemented |  |
| UBU-070 | Auditd | Auditd: immutable mode (-e 2) | CIS | Implemented |  |
| UBU-071 | Auditd | Auditd: max log file size action = keep_logs | CIS | Implemented |  |
| UBU-072 | File Perms | /etc/passwd = 644, root:root | CIS | Implemented |  |
| UBU-073 | File Perms | /etc/shadow = 640, root:shadow | CIS | Implemented |  |
| UBU-074 | File Perms | /etc/group = 644, root:root | CIS | Implemented |  |
| UBU-075 | File Perms | /etc/gshadow = 640, root:shadow | CIS | Implemented |  |
| UBU-076 | File Perms | /etc/crontab = 600, root:root | CIS | Implemented |  |
| UBU-077 | File Perms | /etc/ssh/sshd_config = 600, root:root | CIS | Implemented |  |
| UBU-078 | File Perms | Sticky bit on world-writable dirs | CIS | Implemented |  |
| UBU-079 | File Perms | No world-writable files (scan + report) | CIS | Implemented |  |
| UBU-080 | File Perms | No unowned files (scan + report) | CIS | Implemented |  |
| UBU-081 | File Perms | No legacy '+' entries in passwd/shadow/group | CIS | Implemented |  |
| UBU-082 | File Perms | No UID 0 accounts except root | CIS | Implemented |  |
| UBU-083 | Filesystem | /tmp: nodev,nosuid,noexec mount options | CIS | Implemented |  |
| UBU-084 | Filesystem | /dev/shm: nodev,nosuid,noexec | CIS | Implemented |  |
| UBU-085 | Filesystem | Disable core dumps (/etc/security/limits.conf) | CIS | Implemented |  |
| UBU-086 | Filesystem | GRUB password protection | CIS | Not Implemented | Requires generating password hash interactively. Cannot be automated without exposing plaintext password. |
| UBU-087 | User Accounts | Lock system accounts (daemon, bin, sys, etc.) | CIS | Implemented |  |
| UBU-088 | User Accounts | Disable root login on non-console TTYs (/etc/securetty) | CIS | Implemented |  |
| UBU-089 | User Accounts | Ensure no accounts with empty passwords | CIS | Implemented |  |
| UBU-090 | User Accounts | Default umask = 027 (/etc/bash.bashrc, /etc/profile) | CIS | Implemented |  |
| UBU-091 | Cron | Restrict cron to authorized users (cron.allow) | CIS | Implemented |  |
| UBU-092 | Cron | Restrict at to authorized users (at.allow) | CIS | Implemented |  |
| UBU-093 | Screen Lock | GNOME: lock-delay = 300 seconds (ISSP: 5 min) | ISSP §4.2 | Implemented |  |
| UBU-094 | Screen Lock | GNOME: lock-enabled = true | ISSP §4.2 | Implemented |  |
| UBU-095 | Screen Lock | GNOME: idle-delay = 300 seconds | ISSP §4.2 | Implemented |  |
| UBU-096 | Updates | Install and configure unattended-upgrades | ISSP §5.1 | Implemented |  |
| UBU-097 | Updates | Enable automatic security updates | ISSP §5.1 + CIS | Implemented |  |
| UBU-098 | Integrity | Install AIDE (file integrity monitoring) | CIS | Implemented |  |
| UBU-099 | Integrity | AIDE: initialize database | CIS | Implemented |  |
| UBU-100 | Integrity | AIDE: daily check cron job | CIS | Implemented |  |
| UBU-101 | Logging | rsyslog: log file permissions (640) | CIS | Implemented |  |
| UBU-102 | Logging | logrotate: configured | CIS | Implemented |  |
| UBU-103 | Logging | NTP/chrony time synchronization | CIS | Implemented |  |
| UBU-104 | Logging | Disable Ctrl+Alt+Del reboot | CIS | Implemented |  |
| UBU-105 | Banners | /etc/motd: legal warning configured | CIS + ISSP | Implemented |  |
| UBU-106 | Banners | /etc/issue: pre-login banner | CIS | Implemented |  |
| UBU-107 | Banners | /etc/issue.net: network banner | CIS | Implemented |  |
| UBU-108 | Sudo | Sudo: requires password | CIS | Implemented |  |
| UBU-109 | Sudo | Sudo: timestamp_timeout = 5 min | CIS | Implemented |  |
| UBU-110 | Encryption | Check LUKS encryption status (report if not encrypted) | ISSP §5.1 | Implemented | Script checks and reports. Enabling LUKS on existing system requires full reinstall. |
| UBU-111 | USB | Disable USB storage module (usb-storage) | CIS | Not Implemented | May break legitimate USB use (keyboards, drives). Admin must decide per-machine policy. |
| UBU-112 | ISSP | Session timeout in SSH = 5 min | ISSP §4.2 | Implemented | Via UBU-029/030 |
| UBU-113 | ISSP | VPN enforcement | ISSP §4.2 | Not Implemented | Requires VPN client/gateway infrastructure. Script checks VPN client installation and reports. |

