"""
modules/report.py — Compliance report generator.

Produces two output files after each hardening run (or on demand with
--report-only):

  IMPLEMENTATION.md   Plain-text Markdown table, one row per hardening item,
                      with status (Implemented / Not Implemented / Manual) and
                      the reason when a control was not automated.

  IMPLEMENTATION.ods  LibreOffice Calc spreadsheet with three sheets:
                        • Windows DC  — all WDC-xxx items
                        • Ubuntu      — all UBU-xxx items
                        • Summary     — per-OS totals by status
                      Rows are color-coded: green = Implemented,
                      red = Not Implemented, yellow = Manual.

The canonical list of all hardening items is defined in this module
(WINDOWS_DC_ITEMS and UBUNTU_ITEMS).  The hardening modules (windows_dc.py,
ubuntu.py) update status in-memory and pass the updated lists to
generate_reports(); when called with no arguments the module-level defaults
are used (all items at their pre-set status).

Dependency: odfpy >= 1.4.1  (pip install odfpy).  If the library is absent,
the .ods file is skipped with a warning — the Markdown report is always
generated.
"""

import os
from datetime import datetime
from typing import Dict, List, Optional

from modules.logger import log_ok, log_warn

# ── Try to import odfpy at module load time so the import error is surfaced ──
# early rather than at the moment write_ods() is first called.  If the library
# is not installed we set a flag and skip ODS generation gracefully.
try:
    from odf.opendocument import OpenDocumentSpreadsheet
    from odf.style import Style, TableCellProperties, TextProperties
    from odf.table import Table, TableCell, TableRow
    from odf.text import P
    _ODF_AVAILABLE = True
except ImportError:
    _ODF_AVAILABLE = False

# ── Status string constants ───────────────────────────────────────────────────
# Use these everywhere instead of raw strings to avoid typos and make
# global search/replace easy if the wording ever changes.
STATUS_IMPLEMENTED     = "Implemented"
STATUS_NOT_IMPLEMENTED = "Not Implemented"
STATUS_MANUAL          = "Manual"


class HardeningItem:
    """
    Represents a single hardening control from the CIS benchmark or ISSP.

    Attributes:
        item_id     Unique identifier, e.g. "WDC-001" or "UBU-042".
        category    High-level grouping, e.g. "Account Policy", "SSH", "Audit Policy".
        description Human-readable description of the setting and its target value.
        source      Normative reference, e.g. "CIS 1.1.1" or "ISSP §7.1".
        status      One of STATUS_IMPLEMENTED, STATUS_NOT_IMPLEMENTED, STATUS_MANUAL.
        reason      Explanation when status is not Implemented (empty string otherwise).
    """

    def __init__(self, item_id: str, category: str, description: str,
                 source: str, status: str, reason: str = "") -> None:
        self.item_id     = item_id
        self.category    = category
        self.description = description
        self.source      = source
        self.status      = status
        self.reason      = reason

    def to_dict(self) -> Dict[str, str]:
        """Return a plain dict representation suitable for serialisation."""
        return {
            "ID":                        self.item_id,
            "Category":                  self.category,
            "Hardening Point":           self.description,
            "Source":                    self.source,
            "Status":                    self.status,
            "Reason if Not Implemented": self.reason,
        }


# ─── Master hardening item tables ────────────────────────────────────────────
# These lists are the single source of truth for every hardening control.
# Each entry maps directly to one row in IMPLEMENTATION.md and IMPLEMENTATION.ods.
#
# HardeningItem arguments:  item_id, category, description, source, status[, reason]
#
# Status values:
#   STATUS_IMPLEMENTED     — the script applies this control automatically
#   STATUS_NOT_IMPLEMENTED — the script does NOT apply it; reason is required
#   STATUS_MANUAL          — procedural/org control; cannot be automated
#
# Windows DC items (WDC-001 … WDC-351) follow the CIS Windows Server 2025
# Benchmark v2.0.0, Level 1, Domain Controller profile, supplemented by
# company ISSP (ISO 27002 v2) controls.

WINDOWS_DC_ITEMS: List[HardeningItem] = [
    # ── CIS 1.1 — Account Policies / Password Policy ─────────────────────────
    HardeningItem("WDC-001","Account Policy","Password history = 24","CIS 1.1.1",STATUS_IMPLEMENTED),
    HardeningItem("WDC-002","Account Policy","Max password age = 90 days","CIS 1.1.2 + ISSP §7.1",STATUS_IMPLEMENTED),
    HardeningItem("WDC-003","Account Policy","Min password age = 1 day","CIS 1.1.3",STATUS_IMPLEMENTED),
    HardeningItem("WDC-004","Account Policy","Min password length = 14 chars","CIS 1.1.4",STATUS_IMPLEMENTED),
    HardeningItem("WDC-005","Account Policy","Password complexity = Enabled","CIS 1.1.5",STATUS_IMPLEMENTED),
    HardeningItem("WDC-006","Account Policy","Relax min password length limits = Enabled","CIS 1.1.6",STATUS_IMPLEMENTED),
    HardeningItem("WDC-007","Account Policy","Store passwords reversible encryption = Disabled","CIS 1.1.7",STATUS_IMPLEMENTED),
    HardeningItem("WDC-008","Account Lockout","Account lockout duration = 15 min","CIS 1.2.1",STATUS_IMPLEMENTED),
    HardeningItem("WDC-009","Account Lockout","Account lockout threshold = 5","CIS 1.2.2",STATUS_IMPLEMENTED),
    HardeningItem("WDC-010","Account Lockout","Reset lockout counter after = 15 min","CIS 1.2.4",STATUS_IMPLEMENTED),
    HardeningItem("WDC-011","User Rights","Access Credential Manager = No One","CIS 2.2.1",STATUS_IMPLEMENTED),
    HardeningItem("WDC-012","User Rights","Access computer from network (DC) = Admins, AuthUsers, EntDomainCtrlrs","CIS 2.2.2",STATUS_IMPLEMENTED),
    HardeningItem("WDC-013","User Rights","Act as part of OS = No One","CIS 2.2.4",STATUS_IMPLEMENTED),
    HardeningItem("WDC-014","User Rights","Add workstations to domain = Administrators","CIS 2.2.5",STATUS_IMPLEMENTED),
    HardeningItem("WDC-015","User Rights","Adjust memory quotas = Admins, LOCAL SERVICE, NETWORK SERVICE","CIS 2.2.6",STATUS_IMPLEMENTED),
    HardeningItem("WDC-016","User Rights","Allow log on locally (DC) = Admins, Enterprise Domain Controllers","CIS 2.2.7",STATUS_IMPLEMENTED),
    HardeningItem("WDC-017","User Rights","Allow log on through RDS (DC) = Administrators","CIS 2.2.9",STATUS_IMPLEMENTED),
    HardeningItem("WDC-018","User Rights","Back up files and directories = Administrators","CIS 2.2.11",STATUS_IMPLEMENTED),
    HardeningItem("WDC-019","User Rights","Change system time = Admins, LOCAL SERVICE","CIS 2.2.12",STATUS_IMPLEMENTED),
    HardeningItem("WDC-020","User Rights","Create a pagefile = Administrators","CIS 2.2.13",STATUS_IMPLEMENTED),
    HardeningItem("WDC-021","User Rights","Create a token object = No One","CIS 2.2.14",STATUS_IMPLEMENTED),
    HardeningItem("WDC-022","User Rights","Create global objects = Admins, LOCAL SERVICE, NETWORK SERVICE, SERVICE","CIS 2.2.15",STATUS_IMPLEMENTED),
    HardeningItem("WDC-023","User Rights","Create permanent shared objects = No One","CIS 2.2.16",STATUS_IMPLEMENTED),
    HardeningItem("WDC-024","User Rights","Create symbolic links (DC) = Administrators","CIS 2.2.17",STATUS_IMPLEMENTED),
    HardeningItem("WDC-025","User Rights","Debug programs = Administrators","CIS 2.2.19",STATUS_IMPLEMENTED),
    HardeningItem("WDC-026","User Rights","Deny access from network (DC) = Guests","CIS 2.2.20",STATUS_IMPLEMENTED),
    HardeningItem("WDC-027","User Rights","Deny log on as batch job = Guests","CIS 2.2.22",STATUS_IMPLEMENTED),
    HardeningItem("WDC-028","User Rights","Deny log on as service = Guests","CIS 2.2.23",STATUS_IMPLEMENTED),
    HardeningItem("WDC-029","User Rights","Deny log on locally = Guests","CIS 2.2.24",STATUS_IMPLEMENTED),
    HardeningItem("WDC-030","User Rights","Deny log on through RDS (DC) = Guests","CIS 2.2.25",STATUS_IMPLEMENTED),
    HardeningItem("WDC-031","User Rights","Enable trusted delegation (DC) = Administrators","CIS 2.2.27",STATUS_IMPLEMENTED),
    HardeningItem("WDC-032","User Rights","Force shutdown from remote = Administrators","CIS 2.2.29",STATUS_IMPLEMENTED),
    HardeningItem("WDC-033","User Rights","Generate security audits = LOCAL SERVICE, NETWORK SERVICE","CIS 2.2.30",STATUS_IMPLEMENTED),
    HardeningItem("WDC-034","User Rights","Impersonate client after auth (DC) = Admins, LOCAL SERVICE, NETWORK SERVICE, SERVICE","CIS 2.2.31",STATUS_IMPLEMENTED),
    HardeningItem("WDC-035","User Rights","Increase scheduling priority = Admins, Window Manager Group","CIS 2.2.33",STATUS_IMPLEMENTED),
    HardeningItem("WDC-036","User Rights","Load and unload device drivers = Administrators","CIS 2.2.34",STATUS_IMPLEMENTED),
    HardeningItem("WDC-037","User Rights","Lock pages in memory = No One","CIS 2.2.35",STATUS_IMPLEMENTED),
    HardeningItem("WDC-038","User Rights","Log on as batch job (DC) = Administrators","CIS 2.2.36",STATUS_IMPLEMENTED),
    HardeningItem("WDC-039","User Rights","Manage auditing and security log (DC) = Administrators","CIS 2.2.37",STATUS_IMPLEMENTED),
    HardeningItem("WDC-040","User Rights","Modify an object label = No One","CIS 2.2.39",STATUS_IMPLEMENTED),
    HardeningItem("WDC-041","User Rights","Modify firmware environment values = Administrators","CIS 2.2.40",STATUS_IMPLEMENTED),
    HardeningItem("WDC-042","User Rights","Perform volume maintenance tasks = Administrators","CIS 2.2.41",STATUS_IMPLEMENTED),
    HardeningItem("WDC-043","User Rights","Profile single process = Administrators","CIS 2.2.42",STATUS_IMPLEMENTED),
    HardeningItem("WDC-044","User Rights","Profile system performance = Admins, NT SERVICE\\WdiServiceHost","CIS 2.2.43",STATUS_IMPLEMENTED),
    HardeningItem("WDC-045","User Rights","Replace process level token = LOCAL SERVICE, NETWORK SERVICE","CIS 2.2.44",STATUS_IMPLEMENTED),
    HardeningItem("WDC-046","User Rights","Restore files and directories = Administrators","CIS 2.2.45",STATUS_IMPLEMENTED),
    HardeningItem("WDC-047","User Rights","Shut down the system = Administrators","CIS 2.2.46",STATUS_IMPLEMENTED),
    HardeningItem("WDC-048","User Rights","Synchronize directory service data (DC) = No One","CIS 2.2.47",STATUS_IMPLEMENTED),
    HardeningItem("WDC-049","User Rights","Take ownership of files = Administrators","CIS 2.2.48",STATUS_IMPLEMENTED),
    HardeningItem("WDC-050","Security Options","Guest account status = Disabled","CIS 2.3.1.1",STATUS_IMPLEMENTED),
    HardeningItem("WDC-051","Security Options","Local blank password = console only = Enabled","CIS 2.3.1.2",STATUS_IMPLEMENTED),
    HardeningItem("WDC-052","Security Options","Rename administrator account","CIS 2.3.1.3",STATUS_IMPLEMENTED),
    HardeningItem("WDC-053","Security Options","Rename guest account","CIS 2.3.1.4",STATUS_IMPLEMENTED),
    HardeningItem("WDC-054","Security Options","Audit: Force subcategory settings = Enabled","CIS 2.3.2.1",STATUS_IMPLEMENTED),
    HardeningItem("WDC-055","Security Options","Audit: Shut down if unable to log = Disabled","CIS 2.3.2.2",STATUS_IMPLEMENTED),
    HardeningItem("WDC-056","Security Options","Devices: Prevent printer driver install = Enabled","CIS 2.3.4.1",STATUS_IMPLEMENTED),
    HardeningItem("WDC-057","Security Options","DC: Allow server operators schedule tasks = Disabled","CIS 2.3.5.1",STATUS_IMPLEMENTED),
    HardeningItem("WDC-058","Security Options","DC: LDAP server channel binding = Always","CIS 2.3.5.3",STATUS_IMPLEMENTED),
    HardeningItem("WDC-059","Security Options","DC: LDAP server signing = Enabled","CIS 2.3.5.4",STATUS_IMPLEMENTED),
    HardeningItem("WDC-060","Security Options","DC: Refuse machine account password changes = Disabled","CIS 2.3.5.5",STATUS_IMPLEMENTED),
    HardeningItem("WDC-061","Security Options","Domain member: Digitally encrypt secure channel (always) = Enabled","CIS 2.3.6.1",STATUS_IMPLEMENTED),
    HardeningItem("WDC-062","Security Options","Domain member: Digitally encrypt secure channel (when possible) = Enabled","CIS 2.3.6.2",STATUS_IMPLEMENTED),
    HardeningItem("WDC-063","Security Options","Domain member: Digitally sign secure channel (when possible) = Enabled","CIS 2.3.6.3",STATUS_IMPLEMENTED),
    HardeningItem("WDC-064","Security Options","Domain member: Disable machine account password changes = Disabled","CIS 2.3.6.4",STATUS_IMPLEMENTED),
    HardeningItem("WDC-065","Security Options","Domain member: Max machine account password age = 30 days","CIS 2.3.6.5",STATUS_IMPLEMENTED),
    HardeningItem("WDC-066","Security Options","Domain member: Require strong session key = Enabled","CIS 2.3.6.6",STATUS_IMPLEMENTED),
    HardeningItem("WDC-067","Security Options","Interactive logon: Don't require CTRL+ALT+DEL = Disabled","CIS 2.3.7.1",STATUS_IMPLEMENTED),
    HardeningItem("WDC-068","Security Options","Interactive logon: Don't display last signed-in = Enabled","CIS 2.3.7.2",STATUS_IMPLEMENTED),
    HardeningItem("WDC-069","Security Options","Interactive logon: Machine inactivity limit = 300 seconds","CIS 2.3.7.3 + ISSP §4.2",STATUS_IMPLEMENTED),
    HardeningItem("WDC-070","Security Options","Interactive logon: Message text = Configured","CIS 2.3.7.4",STATUS_IMPLEMENTED),
    HardeningItem("WDC-071","Security Options","Interactive logon: Message title = Configured","CIS 2.3.7.5",STATUS_IMPLEMENTED),
    HardeningItem("WDC-072","Security Options","Interactive logon: Smart card removal = Lock Workstation","CIS 2.3.7.9",STATUS_IMPLEMENTED),
    HardeningItem("WDC-073","Security Options","MS network client: Digitally sign (always) = Enabled","CIS 2.3.8.1",STATUS_IMPLEMENTED),
    HardeningItem("WDC-074","Security Options","MS network client: Send unencrypted password = Disabled","CIS 2.3.8.2",STATUS_IMPLEMENTED),
    HardeningItem("WDC-075","Security Options","MS network server: Idle time before suspend = 15 min","CIS 2.3.9.1",STATUS_IMPLEMENTED),
    HardeningItem("WDC-076","Security Options","MS network server: Digitally sign (always) = Enabled","CIS 2.3.9.2",STATUS_IMPLEMENTED),
    HardeningItem("WDC-077","Security Options","MS network server: Disconnect when logon hours expire = Enabled","CIS 2.3.9.3",STATUS_IMPLEMENTED),
    HardeningItem("WDC-078","Security Options","Network access: Allow anonymous SID/Name translation = Disabled","CIS 2.3.10.1",STATUS_IMPLEMENTED),
    HardeningItem("WDC-079","Security Options","Network access: No anonymous SAM enumeration = Enabled","CIS 2.3.10.2",STATUS_IMPLEMENTED),
    HardeningItem("WDC-080","Security Options","Network access: No anonymous SAM accounts and shares = Enabled","CIS 2.3.10.3",STATUS_IMPLEMENTED),
    HardeningItem("WDC-081","Security Options","Network access: No password/credential storage = Enabled","CIS 2.3.10.4",STATUS_IMPLEMENTED),
    HardeningItem("WDC-082","Security Options","Network access: Everyone permissions to anonymous = Disabled","CIS 2.3.10.5",STATUS_IMPLEMENTED),
    HardeningItem("WDC-083","Security Options","Network access: Named Pipes anonymously (DC) = configured","CIS 2.3.10.6",STATUS_IMPLEMENTED),
    HardeningItem("WDC-084","Security Options","Network access: Restrict anonymous Named Pipes and Shares = Enabled","CIS 2.3.10.10",STATUS_IMPLEMENTED),
    HardeningItem("WDC-085","Security Options","Network access: Restrict clients remote calls to SAM = Administrators","CIS 2.3.10.11",STATUS_IMPLEMENTED),
    HardeningItem("WDC-086","Security Options","Network access: Shares accessible anonymously = None","CIS 2.3.10.12",STATUS_IMPLEMENTED),
    HardeningItem("WDC-087","Security Options","Network access: Sharing and security model = Classic","CIS 2.3.10.13",STATUS_IMPLEMENTED),
    HardeningItem("WDC-088","Security Options","Network security: Allow LocalSystem NULL session fallback = Disabled","CIS 2.3.11.2",STATUS_IMPLEMENTED),
    HardeningItem("WDC-089","Security Options","Network security: Allow PKU2U auth = Disabled","CIS 2.3.11.3",STATUS_IMPLEMENTED),
    HardeningItem("WDC-090","Security Options","Network security: Kerberos encryption = AES128+AES256","CIS 2.3.11.4",STATUS_IMPLEMENTED),
    HardeningItem("WDC-091","Security Options","Network security: LAN Manager auth = NTLMv2, refuse LM+NTLM","CIS 2.3.11.6",STATUS_IMPLEMENTED),
    HardeningItem("WDC-092","Security Options","Network security: LDAP client signing = Negotiate signing","CIS 2.3.11.8",STATUS_IMPLEMENTED),
    HardeningItem("WDC-093","Security Options","Network security: Min session NTLM SSP clients = NTLMv2+128bit","CIS 2.3.11.9",STATUS_IMPLEMENTED),
    HardeningItem("WDC-094","Security Options","Network security: Min session NTLM SSP servers = NTLMv2+128bit","CIS 2.3.11.10",STATUS_IMPLEMENTED),
    HardeningItem("WDC-095","Security Options","Network security: Restrict NTLM: Audit Incoming = All accounts","CIS 2.3.11.11",STATUS_IMPLEMENTED),
    HardeningItem("WDC-096","Security Options","Network security: Restrict NTLM: Audit in domain (DC) = All","CIS 2.3.11.12",STATUS_IMPLEMENTED),
    HardeningItem("WDC-097","Security Options","Network security: Restrict NTLM: Outgoing = Audit all","CIS 2.3.11.13",STATUS_IMPLEMENTED),
    HardeningItem("WDC-098","Security Options","Shutdown: Allow without logon = Disabled","CIS 2.3.13.1",STATUS_IMPLEMENTED),
    HardeningItem("WDC-099","Security Options","System objects: Strengthen default permissions = Enabled","CIS 2.3.15.2",STATUS_IMPLEMENTED),
    HardeningItem("WDC-100","UAC","UAC: Admin Approval Mode for built-in admin = Enabled","CIS 2.3.17.1",STATUS_IMPLEMENTED),
    HardeningItem("WDC-101","UAC","UAC: Elevation prompt for admins = Consent on secure desktop","CIS 2.3.17.2",STATUS_IMPLEMENTED),
    HardeningItem("WDC-102","UAC","UAC: Elevation prompt for standard users = Auto deny","CIS 2.3.17.3",STATUS_IMPLEMENTED),
    HardeningItem("WDC-103","UAC","UAC: Detect app installations and prompt = Enabled","CIS 2.3.17.4",STATUS_IMPLEMENTED),
    HardeningItem("WDC-104","UAC","UAC: Only elevate UIAccess in secure locations = Enabled","CIS 2.3.17.5",STATUS_IMPLEMENTED),
    HardeningItem("WDC-105","UAC","UAC: Run all admins in Admin Approval Mode = Enabled","CIS 2.3.17.6",STATUS_IMPLEMENTED),
    HardeningItem("WDC-106","UAC","UAC: Switch to secure desktop when prompting = Enabled","CIS 2.3.17.7",STATUS_IMPLEMENTED),
    HardeningItem("WDC-107","UAC","UAC: Virtualize file/registry write failures = Enabled","CIS 2.3.17.8",STATUS_IMPLEMENTED),
    HardeningItem("WDC-108","System Services","Print Spooler (DC) = Disabled and Stopped","CIS 5.1",STATUS_IMPLEMENTED),
    HardeningItem("WDC-109","Firewall","Domain profile: Firewall state = On","CIS 9.1.1",STATUS_IMPLEMENTED),
    HardeningItem("WDC-110","Firewall","Domain profile: Inbound = Block (default)","CIS 9.1.2",STATUS_IMPLEMENTED),
    HardeningItem("WDC-111","Firewall","Domain profile: Display notification = No","CIS 9.1.3",STATUS_IMPLEMENTED),
    HardeningItem("WDC-112","Firewall","Domain profile: Log size = 16384 KB","CIS 9.1.5",STATUS_IMPLEMENTED),
    HardeningItem("WDC-113","Firewall","Domain profile: Log dropped packets = Yes","CIS 9.1.6",STATUS_IMPLEMENTED),
    HardeningItem("WDC-114","Firewall","Domain profile: Log successful connections = Yes","CIS 9.1.7",STATUS_IMPLEMENTED),
    HardeningItem("WDC-115","Firewall","Private profile: Firewall state = On","CIS 9.2.1",STATUS_IMPLEMENTED),
    HardeningItem("WDC-116","Firewall","Private profile: Inbound = Block","CIS 9.2.2",STATUS_IMPLEMENTED),
    HardeningItem("WDC-117","Firewall","Private profile: Log configured","CIS 9.2.4-9.2.7",STATUS_IMPLEMENTED),
    HardeningItem("WDC-118","Firewall","Public profile: Firewall state = On","CIS 9.3.1",STATUS_IMPLEMENTED),
    HardeningItem("WDC-119","Firewall","Public profile: Inbound = Block","CIS 9.3.2",STATUS_IMPLEMENTED),
    HardeningItem("WDC-120","Firewall","Public profile: Apply local firewall rules = No","CIS 9.3.4",STATUS_IMPLEMENTED),
    HardeningItem("WDC-121","Firewall","Public profile: Apply local connection security rules = No","CIS 9.3.5",STATUS_IMPLEMENTED),
    HardeningItem("WDC-122","Firewall","Public profile: Log configured","CIS 9.3.6-9.3.9",STATUS_IMPLEMENTED),
    HardeningItem("WDC-123","Audit Policy","Audit Credential Validation = Success+Failure","CIS 17.1.1",STATUS_IMPLEMENTED),
    HardeningItem("WDC-124","Audit Policy","Audit Kerberos Authentication Service (DC) = Success+Failure","CIS 17.1.2",STATUS_IMPLEMENTED),
    HardeningItem("WDC-125","Audit Policy","Audit Kerberos Service Ticket Operations (DC) = Success+Failure","CIS 17.1.3",STATUS_IMPLEMENTED),
    HardeningItem("WDC-126","Audit Policy","Audit Application Group Management = Success+Failure","CIS 17.2.1",STATUS_IMPLEMENTED),
    HardeningItem("WDC-127","Audit Policy","Audit Computer Account Management (DC) = Success","CIS 17.2.2",STATUS_IMPLEMENTED),
    HardeningItem("WDC-128","Audit Policy","Audit Distribution Group Management (DC) = Success","CIS 17.2.3",STATUS_IMPLEMENTED),
    HardeningItem("WDC-129","Audit Policy","Audit Other Account Management Events (DC) = Success","CIS 17.2.4",STATUS_IMPLEMENTED),
    HardeningItem("WDC-130","Audit Policy","Audit Security Group Management = Success","CIS 17.2.5",STATUS_IMPLEMENTED),
    HardeningItem("WDC-131","Audit Policy","Audit User Account Management = Success+Failure","CIS 17.2.6",STATUS_IMPLEMENTED),
    HardeningItem("WDC-132","Audit Policy","Audit PNP Activity = Success","CIS 17.3.1",STATUS_IMPLEMENTED),
    HardeningItem("WDC-133","Audit Policy","Audit Process Creation = Success","CIS 17.3.2",STATUS_IMPLEMENTED),
    HardeningItem("WDC-134","Audit Policy","Audit Directory Service Access (DC) = Failure","CIS 17.4.1",STATUS_IMPLEMENTED),
    HardeningItem("WDC-135","Audit Policy","Audit Directory Service Changes (DC) = Success","CIS 17.4.2",STATUS_IMPLEMENTED),
    HardeningItem("WDC-136","Audit Policy","Audit Account Lockout = Failure","CIS 17.5.1",STATUS_IMPLEMENTED),
    HardeningItem("WDC-137","Audit Policy","Audit Group Membership = Success","CIS 17.5.2",STATUS_IMPLEMENTED),
    HardeningItem("WDC-138","Audit Policy","Audit Logoff = Success","CIS 17.5.3",STATUS_IMPLEMENTED),
    HardeningItem("WDC-139","Audit Policy","Audit Logon = Success+Failure","CIS 17.5.4",STATUS_IMPLEMENTED),
    HardeningItem("WDC-140","Audit Policy","Audit Other Logon/Logoff Events = Success+Failure","CIS 17.5.5",STATUS_IMPLEMENTED),
    HardeningItem("WDC-141","Audit Policy","Audit Special Logon = Success","CIS 17.5.6",STATUS_IMPLEMENTED),
    HardeningItem("WDC-142","Audit Policy","Audit Detailed File Share = Failure","CIS 17.6.1",STATUS_IMPLEMENTED),
    HardeningItem("WDC-143","Audit Policy","Audit File Share = Success+Failure","CIS 17.6.2",STATUS_IMPLEMENTED),
    HardeningItem("WDC-144","Audit Policy","Audit Other Object Access Events = Success+Failure","CIS 17.6.3",STATUS_IMPLEMENTED),
    HardeningItem("WDC-145","Audit Policy","Audit Removable Storage = Success+Failure","CIS 17.6.4",STATUS_IMPLEMENTED),
    HardeningItem("WDC-146","Audit Policy","Audit Audit Policy Change = Success","CIS 17.7.1",STATUS_IMPLEMENTED),
    HardeningItem("WDC-147","Audit Policy","Audit Authentication Policy Change = Success","CIS 17.7.2",STATUS_IMPLEMENTED),
    HardeningItem("WDC-148","Audit Policy","Audit Authorization Policy Change = Success","CIS 17.7.3",STATUS_IMPLEMENTED),
    HardeningItem("WDC-149","Audit Policy","Audit MPSSVC Rule-Level Policy Change = Success+Failure","CIS 17.7.4",STATUS_IMPLEMENTED),
    HardeningItem("WDC-150","Audit Policy","Audit Other Policy Change Events = Failure","CIS 17.7.5",STATUS_IMPLEMENTED),
    HardeningItem("WDC-151","Audit Policy","Audit Sensitive Privilege Use = Success+Failure","CIS 17.8.1",STATUS_IMPLEMENTED),
    HardeningItem("WDC-152","Audit Policy","Audit IPsec Driver = Success+Failure","CIS 17.9.1",STATUS_IMPLEMENTED),
    HardeningItem("WDC-153","Audit Policy","Audit Other System Events = Success+Failure","CIS 17.9.2",STATUS_IMPLEMENTED),
    HardeningItem("WDC-154","Audit Policy","Audit Security State Change = Success","CIS 17.9.3",STATUS_IMPLEMENTED),
    HardeningItem("WDC-155","Audit Policy","Audit Security System Extension = Success","CIS 17.9.4",STATUS_IMPLEMENTED),
    HardeningItem("WDC-156","Audit Policy","Audit System Integrity = Success+Failure","CIS 17.9.5",STATUS_IMPLEMENTED),
    HardeningItem("WDC-157","Admin Templates","Prevent lock screen camera = Enabled","CIS 18.1.1.1",STATUS_IMPLEMENTED),
    HardeningItem("WDC-158","Admin Templates","Prevent lock screen slide show = Enabled","CIS 18.1.1.2",STATUS_IMPLEMENTED),
    HardeningItem("WDC-159","Admin Templates","Allow online speech recognition = Disabled","CIS 18.1.2.2",STATUS_IMPLEMENTED),
    HardeningItem("WDC-160","Admin Templates","Allow Online Tips = Disabled","CIS 18.1.3",STATUS_IMPLEMENTED),
    HardeningItem("WDC-161","Admin Templates","LAPS: Configure password backup to AD = Enabled","CIS 18.9.26.1",STATUS_IMPLEMENTED),
    HardeningItem("WDC-162","Admin Templates","LAPS: No expiration > policy = Enabled","CIS 18.9.26.2",STATUS_IMPLEMENTED),
    HardeningItem("WDC-163","Admin Templates","LAPS: Enable password encryption = Enabled","CIS 18.9.26.3",STATUS_IMPLEMENTED),
    HardeningItem("WDC-164","Admin Templates","LAPS: Password complexity = Large+Small+Num+Special","CIS 18.9.26.4",STATUS_IMPLEMENTED),
    HardeningItem("WDC-165","Admin Templates","LAPS: Password length = 15+","CIS 18.9.26.5",STATUS_IMPLEMENTED),
    HardeningItem("WDC-166","Admin Templates","LAPS: Password age = 30 days","CIS 18.9.26.6",STATUS_IMPLEMENTED),
    HardeningItem("WDC-167","Admin Templates","LAPS: Post-auth grace period = 8h","CIS 18.9.26.7",STATUS_IMPLEMENTED),
    HardeningItem("WDC-168","Admin Templates","LAPS: Post-auth actions = Reset+Logoff","CIS 18.9.26.8",STATUS_IMPLEMENTED),
    HardeningItem("WDC-169","Admin Templates","MS Security Guide: UAC restrictions local accounts = Enabled","CIS 18.4.1",STATUS_IMPLEMENTED),
    HardeningItem("WDC-170","Admin Templates","MS Security Guide: SMBv1 client = Disabled","CIS 18.4.2",STATUS_IMPLEMENTED),
    HardeningItem("WDC-171","Admin Templates","MS Security Guide: SMBv1 server = Disabled","CIS 18.4.3",STATUS_IMPLEMENTED),
    HardeningItem("WDC-172","Admin Templates","MS Security Guide: Certificate Padding = Enabled","CIS 18.4.4",STATUS_IMPLEMENTED),
    HardeningItem("WDC-173","Admin Templates","MS Security Guide: SEHOP = Enabled","CIS 18.4.5",STATUS_IMPLEMENTED),
    HardeningItem("WDC-174","Admin Templates","MS Security Guide: NetBT NodeType = P-node","CIS 18.4.6",STATUS_IMPLEMENTED),
    HardeningItem("WDC-175","Admin Templates","MSS: AutoAdminLogon = Disabled","CIS 18.5.1",STATUS_IMPLEMENTED),
    HardeningItem("WDC-176","Admin Templates","MSS: DisableIPSourceRouting IPv6 = Highest protection","CIS 18.5.2",STATUS_IMPLEMENTED),
    HardeningItem("WDC-177","Admin Templates","MSS: DisableIPSourceRouting IPv4 = Highest protection","CIS 18.5.3",STATUS_IMPLEMENTED),
    HardeningItem("WDC-178","Admin Templates","MSS: EnableICMPRedirect = Disabled","CIS 18.5.4",STATUS_IMPLEMENTED),
    HardeningItem("WDC-179","Admin Templates","MSS: KeepAliveTime = 300000ms","CIS 18.5.5",STATUS_IMPLEMENTED),
    HardeningItem("WDC-180","Admin Templates","MSS: NoNameReleaseOnDemand = Enabled","CIS 18.5.6",STATUS_IMPLEMENTED),
    HardeningItem("WDC-181","Admin Templates","MSS: PerformRouterDiscovery = Disabled","CIS 18.5.7",STATUS_IMPLEMENTED),
    HardeningItem("WDC-182","Admin Templates","MSS: SafeDllSearchMode = Enabled","CIS 18.5.8",STATUS_IMPLEMENTED),
    HardeningItem("WDC-183","Admin Templates","MSS: TcpMaxDataRetransmissions IPv6 = 3","CIS 18.5.9",STATUS_IMPLEMENTED),
    HardeningItem("WDC-184","Admin Templates","MSS: TcpMaxDataRetransmissions IPv4 = 3","CIS 18.5.10",STATUS_IMPLEMENTED),
    HardeningItem("WDC-185","Admin Templates","MSS: WarningLevel = 90%","CIS 18.5.11",STATUS_IMPLEMENTED),
    HardeningItem("WDC-186","Admin Templates","DNS: Configure mDNS = Disabled","CIS 18.6.4.1",STATUS_IMPLEMENTED),
    HardeningItem("WDC-187","Admin Templates","DNS: NetBIOS = Disable on public networks","CIS 18.6.4.2",STATUS_IMPLEMENTED),
    HardeningItem("WDC-188","Admin Templates","DNS: Turn off default IPv6 DNS servers = Enabled","CIS 18.6.4.3",STATUS_IMPLEMENTED),
    HardeningItem("WDC-189","Admin Templates","DNS: Turn off multicast name resolution = Enabled","CIS 18.6.4.4",STATUS_IMPLEMENTED),
    HardeningItem("WDC-190","Admin Templates","Fonts: Enable Font Providers = Disabled","CIS 18.6.5.1",STATUS_IMPLEMENTED),
    HardeningItem("WDC-191","Admin Templates","LanMan Server: Audit client encryption/signing = Enabled","CIS 18.6.7.1-7.3",STATUS_IMPLEMENTED),
    HardeningItem("WDC-192","Admin Templates","LanMan Server: Enable authentication rate limiter = Enabled","CIS 18.6.7.4",STATUS_IMPLEMENTED),
    HardeningItem("WDC-193","Admin Templates","LanMan Server: Disable remote mailslots = Enabled","CIS 18.6.7.5",STATUS_IMPLEMENTED),
    HardeningItem("WDC-194","Admin Templates","LanMan Server: Mandate min SMB version 3.1.1","CIS 18.6.7.6",STATUS_IMPLEMENTED),
    HardeningItem("WDC-195","Admin Templates","LanMan Workstation: Require Encryption = Enabled","CIS 18.6.8.7",STATUS_IMPLEMENTED),
    HardeningItem("WDC-196","Admin Templates","LLTDIO driver = Disabled","CIS 18.6.9.1",STATUS_IMPLEMENTED),
    HardeningItem("WDC-197","Admin Templates","RSPNDR driver = Disabled","CIS 18.6.9.2",STATUS_IMPLEMENTED),
    HardeningItem("WDC-198","Admin Templates","Turn off MS Peer-to-Peer Networking = Enabled","CIS 18.6.10.2",STATUS_IMPLEMENTED),
    HardeningItem("WDC-199","Admin Templates","Prohibit Network Bridge = Enabled","CIS 18.6.11.2",STATUS_IMPLEMENTED),
    HardeningItem("WDC-200","Admin Templates","Prohibit Internet Connection Sharing = Enabled","CIS 18.6.11.3",STATUS_IMPLEMENTED),
    HardeningItem("WDC-201","Admin Templates","Require domain users elevate for network location = Enabled","CIS 18.6.11.4",STATUS_IMPLEMENTED),
    HardeningItem("WDC-202","Admin Templates","Hardened UNC Paths (NETLOGON+SYSVOL) = Mutual Auth+Integrity+Privacy","CIS 18.6.14.1",STATUS_IMPLEMENTED),
    HardeningItem("WDC-203","Admin Templates","Disable IPv6 = 0xff (all disabled)","CIS 18.6.19.2.1",STATUS_IMPLEMENTED),
    HardeningItem("WDC-204","Admin Templates","Minimize simultaneous connections = 3 (no Wi-Fi on Ethernet)","CIS 18.6.21.1",STATUS_IMPLEMENTED),
    HardeningItem("WDC-205","Admin Templates","Allow Print Spooler accept client connections = Disabled","CIS 18.7.1",STATUS_IMPLEMENTED),
    HardeningItem("WDC-206","Admin Templates","Configure Redirection Guard = Enabled","CIS 18.7.2",STATUS_IMPLEMENTED),
    HardeningItem("WDC-207","Admin Templates","RPC outgoing: Protocol = RPC over TCP","CIS 18.7.3",STATUS_IMPLEMENTED),
    HardeningItem("WDC-208","Admin Templates","RPC outgoing: Use authentication = Default","CIS 18.7.4",STATUS_IMPLEMENTED),
    HardeningItem("WDC-209","Admin Templates","RPC listener: Protocols = RPC over TCP","CIS 18.7.5",STATUS_IMPLEMENTED),
    HardeningItem("WDC-210","Admin Templates","RPC listener: Auth = Negotiate or higher","CIS 18.7.6",STATUS_IMPLEMENTED),
    HardeningItem("WDC-211","Admin Templates","RPC over TCP port = 0","CIS 18.7.7",STATUS_IMPLEMENTED),
    HardeningItem("WDC-212","Admin Templates","RPC packet level privacy = Enabled","CIS 18.7.8",STATUS_IMPLEMENTED),
    HardeningItem("WDC-213","Admin Templates","Windows protected print = Enabled","CIS 18.7.9",STATUS_IMPLEMENTED),
    HardeningItem("WDC-214","Admin Templates","Limit print driver install to Admins = Enabled","CIS 18.7.10",STATUS_IMPLEMENTED),
    HardeningItem("WDC-215","Admin Templates","Turn off notifications network usage = Enabled","CIS 18.8.1.1",STATUS_IMPLEMENTED),
    HardeningItem("WDC-216","Admin Templates","Include command line in process creation = Enabled","CIS 18.9.3.1",STATUS_IMPLEMENTED),
    HardeningItem("WDC-217","Admin Templates","Encryption Oracle Remediation = Force Updated Clients","CIS 18.9.4.1",STATUS_IMPLEMENTED),
    HardeningItem("WDC-218","Admin Templates","Remote host: delegate non-exportable credentials = Enabled","CIS 18.9.4.2",STATUS_IMPLEMENTED),
    HardeningItem("WDC-219","Admin Templates","VBS: Turn On = Enabled","CIS 18.9.5.1",STATUS_IMPLEMENTED),
    HardeningItem("WDC-220","Admin Templates","VBS: Platform Security Level = Secure Boot","CIS 18.9.5.2",STATUS_IMPLEMENTED),
    HardeningItem("WDC-221","Admin Templates","VBS: HVCI = Enabled with UEFI lock","CIS 18.9.5.3",STATUS_IMPLEMENTED),
    HardeningItem("WDC-222","Admin Templates","VBS: Require UEFI Memory Attributes Table = True","CIS 18.9.5.4",STATUS_IMPLEMENTED),
    HardeningItem("WDC-223","Admin Templates","VBS: Credential Guard (DC only) = Disabled","CIS 18.9.5.6",STATUS_IMPLEMENTED,"DC must have this DISABLED per CIS"),
    HardeningItem("WDC-224","Admin Templates","VBS: Secure Launch = Enabled","CIS 18.9.5.7",STATUS_IMPLEMENTED),
    HardeningItem("WDC-225","Admin Templates","Kernel DMA Protection: Block All","CIS 18.9.24.1",STATUS_IMPLEMENTED),
    HardeningItem("WDC-226","Admin Templates","Prevent auto download of apps with device metadata","CIS 18.9.7.1.1",STATUS_IMPLEMENTED),
    HardeningItem("WDC-227","Admin Templates","Boot-Start Driver: Good+Unknown+Bad but critical","CIS 18.9.13.1",STATUS_IMPLEMENTED),
    HardeningItem("WDC-228","Admin Templates","LSASS: Allow Custom SSPs/APs (DC) = Disabled","CIS 18.9.27.1",STATUS_IMPLEMENTED),
    HardeningItem("WDC-229","Admin Templates","LSASS: Run as protected process = Enabled with UEFI Lock","CIS 18.9.27.2",STATUS_IMPLEMENTED),
    HardeningItem("WDC-230","Admin Templates","Security policy processing: No apply during periodic background = FALSE","CIS 18.9.19.2",STATUS_IMPLEMENTED),
    HardeningItem("WDC-231","Admin Templates","Security policy processing: Process even if unchanged = TRUE","CIS 18.9.19.3",STATUS_IMPLEMENTED),
    HardeningItem("WDC-232","Admin Templates","Turn off background refresh of Group Policy = Disabled","CIS 18.9.19.5",STATUS_IMPLEMENTED),
    HardeningItem("WDC-233","Admin Templates","Turn off downloading print drivers over HTTP = Enabled","CIS 18.9.20.1.1",STATUS_IMPLEMENTED),
    HardeningItem("WDC-234","Admin Templates","Turn off Internet Connection Wizard = Enabled","CIS 18.9.20.1.4",STATUS_IMPLEMENTED),
    HardeningItem("WDC-235","Admin Templates","Turn off Internet download for Web publishing = Enabled","CIS 18.9.20.1.5",STATUS_IMPLEMENTED),
    HardeningItem("WDC-236","Admin Templates","Turn off printing over HTTP = Enabled","CIS 18.9.20.1.6",STATUS_IMPLEMENTED),
    HardeningItem("WDC-237","Admin Templates","Turn off Registration if URL = Enabled","CIS 18.9.20.1.7",STATUS_IMPLEMENTED),
    HardeningItem("WDC-238","Admin Templates","Turn off Search Companion updates = Enabled","CIS 18.9.20.1.8",STATUS_IMPLEMENTED),
    HardeningItem("WDC-239","Admin Templates","Turn off Windows Messenger CEIP = Enabled","CIS 18.9.20.1.11",STATUS_IMPLEMENTED),
    HardeningItem("WDC-240","Admin Templates","Turn off Windows CEIP = Enabled","CIS 18.9.20.1.12",STATUS_IMPLEMENTED),
    HardeningItem("WDC-241","Admin Templates","Turn off Windows Error Reporting = Enabled","CIS 18.9.20.1.13",STATUS_IMPLEMENTED),
    HardeningItem("WDC-242","Admin Templates","Kerberos: Support device auth = Automatic","CIS 18.9.23.1",STATUS_IMPLEMENTED),
    HardeningItem("WDC-243","Admin Templates","SAM: ROCA-vulnerable WHfB keys (DC) = Block","CIS 18.9.41.1",STATUS_IMPLEMENTED),
    HardeningItem("WDC-244","Admin Templates","SAM: Strong encryption change password (DC) = Allow strong only","CIS 18.9.41.2",STATUS_IMPLEMENTED),
    HardeningItem("WDC-245","Admin Templates","Block user from showing account details at sign-in = Enabled","CIS 18.9.29.1",STATUS_IMPLEMENTED),
    HardeningItem("WDC-246","Admin Templates","Do not display network selection UI = Enabled","CIS 18.9.29.2",STATUS_IMPLEMENTED),
    HardeningItem("WDC-247","Admin Templates","Do not enumerate connected users on domain-joined = Enabled","CIS 18.9.29.3",STATUS_IMPLEMENTED),
    HardeningItem("WDC-248","Admin Templates","Turn off app notifications on lock screen = Enabled","CIS 18.9.29.5",STATUS_IMPLEMENTED),
    HardeningItem("WDC-249","Admin Templates","Turn off convenience PIN sign-in = Disabled","CIS 18.9.29.6",STATUS_IMPLEMENTED),
    HardeningItem("WDC-250","Admin Templates","Block NetBIOS-based DC location = Enabled","CIS 18.9.31.1.1",STATUS_IMPLEMENTED),
    HardeningItem("WDC-251","Admin Templates","Allow Clipboard synchronization = Disabled","CIS 18.9.33.1",STATUS_IMPLEMENTED),
    HardeningItem("WDC-252","Admin Templates","Allow upload of User Activities = Disabled","CIS 18.9.33.2",STATUS_IMPLEMENTED),
    HardeningItem("WDC-253","Admin Templates","Disallow AutoPlay for non-volume devices = Enabled","CIS 18.10.8.1",STATUS_IMPLEMENTED),
    HardeningItem("WDC-254","Admin Templates","Default AutoRun = Do not execute","CIS 18.10.8.2",STATUS_IMPLEMENTED),
    HardeningItem("WDC-255","Admin Templates","Turn off AutoPlay = All drives","CIS 18.10.8.3",STATUS_IMPLEMENTED),
    HardeningItem("WDC-256","Admin Templates","Configure enhanced anti-spoofing = Enabled","CIS 18.10.9.1.1",STATUS_IMPLEMENTED),
    HardeningItem("WDC-257","Admin Templates","Turn off cloud consumer account state content = Enabled","CIS 18.10.13.1",STATUS_IMPLEMENTED),
    HardeningItem("WDC-258","Admin Templates","Turn off cloud optimized content = Enabled","CIS 18.10.13.2",STATUS_IMPLEMENTED),
    HardeningItem("WDC-259","Admin Templates","Allow Diagnostic Data = Required only","CIS 18.10.16.1",STATUS_IMPLEMENTED),
    HardeningItem("WDC-260","Admin Templates","Disable Authenticated Proxy for Connected User Experience = Enabled","CIS 18.10.16.2",STATUS_IMPLEMENTED),
    HardeningItem("WDC-261","Admin Templates","Do not show feedback notifications = Enabled","CIS 18.10.16.3",STATUS_IMPLEMENTED),
    HardeningItem("WDC-262","Admin Templates","Enable OneSettings Auditing = Enabled","CIS 18.10.16.4",STATUS_IMPLEMENTED),
    HardeningItem("WDC-263","Admin Templates","Limit Diagnostic Log Collection = Enabled","CIS 18.10.16.5",STATUS_IMPLEMENTED),
    HardeningItem("WDC-264","Admin Templates","Limit Dump Collection = Enabled","CIS 18.10.16.6",STATUS_IMPLEMENTED),
    HardeningItem("WDC-265","Admin Templates","App Event Log max size = 32768 KB","CIS 18.10.26.1.2",STATUS_IMPLEMENTED),
    HardeningItem("WDC-266","Admin Templates","Security Event Log max size = 196608 KB","CIS 18.10.26.2.2",STATUS_IMPLEMENTED),
    HardeningItem("WDC-267","Admin Templates","Setup Event Log max size = 32768 KB","CIS 18.10.26.3.2",STATUS_IMPLEMENTED),
    HardeningItem("WDC-268","Admin Templates","System Event Log max size = 32768 KB","CIS 18.10.26.4.2",STATUS_IMPLEMENTED),
    HardeningItem("WDC-269","Admin Templates","Turn off heap termination on corruption = Disabled","CIS 18.10.29.4",STATUS_IMPLEMENTED),
    HardeningItem("WDC-270","Admin Templates","Turn off shell protocol protected mode = Disabled","CIS 18.10.29.5",STATUS_IMPLEMENTED),
    HardeningItem("WDC-271","Admin Templates","Allow Use of Camera = Disabled","CIS 18.10.11.1",STATUS_IMPLEMENTED),
    HardeningItem("WDC-272","Admin Templates","Block all consumer Microsoft account auth = Enabled","CIS 18.10.41.1",STATUS_IMPLEMENTED),
    HardeningItem("WDC-273","Admin Templates","Enable EDR in block mode = Enabled","CIS 18.10.42.4.1",STATUS_IMPLEMENTED),
    HardeningItem("WDC-274","Admin Templates","Local override for MAPS reporting = Disabled","CIS 18.10.42.5.1",STATUS_IMPLEMENTED),
    HardeningItem("WDC-275","Admin Templates","Join Microsoft MAPS = Advanced","CIS 18.10.42.5.2",STATUS_IMPLEMENTED),
    HardeningItem("WDC-276","Admin Templates","Configure ASR rules = Enabled","CIS 18.10.42.6.1.1",STATUS_IMPLEMENTED),
    HardeningItem("WDC-277","Admin Templates","Configure ASR rules state","CIS 18.10.42.6.1.2",STATUS_IMPLEMENTED),
    HardeningItem("WDC-278","Admin Templates","Prevent users/apps accessing dangerous websites = Block","CIS 18.10.42.6.3.1",STATUS_IMPLEMENTED),
    HardeningItem("WDC-279","Admin Templates","Real-time protection during OOBE = Enabled","CIS 18.10.42.10.1",STATUS_IMPLEMENTED),
    HardeningItem("WDC-280","Admin Templates","Scan downloaded files = Enabled","CIS 18.10.42.10.2",STATUS_IMPLEMENTED),
    HardeningItem("WDC-281","Admin Templates","Turn off real-time protection = Disabled","CIS 18.10.42.10.3",STATUS_IMPLEMENTED),
    HardeningItem("WDC-282","Admin Templates","Turn on behavior monitoring = Enabled","CIS 18.10.42.10.4",STATUS_IMPLEMENTED),
    HardeningItem("WDC-283","Admin Templates","Turn on script scanning = Enabled","CIS 18.10.42.10.5",STATUS_IMPLEMENTED),
    HardeningItem("WDC-284","Admin Templates","Brute-Force Protection aggressiveness = Medium+","CIS 18.10.42.11.1.1",STATUS_IMPLEMENTED),
    HardeningItem("WDC-285","Admin Templates","Remote Encryption Protection Mode = Audit+","CIS 18.10.42.11.1.2",STATUS_IMPLEMENTED),
    HardeningItem("WDC-286","Admin Templates","Configure Watson events = Disabled","CIS 18.10.42.12.1",STATUS_IMPLEMENTED),
    HardeningItem("WDC-287","Admin Templates","Scan packed executables = Enabled","CIS 18.10.42.13.2",STATUS_IMPLEMENTED),
    HardeningItem("WDC-288","Admin Templates","Scan removable drives = Enabled","CIS 18.10.42.13.3",STATUS_IMPLEMENTED),
    HardeningItem("WDC-289","Admin Templates","Trigger quick scan after 7 days without scan","CIS 18.10.42.13.4",STATUS_IMPLEMENTED),
    HardeningItem("WDC-290","Admin Templates","Turn on email scanning = Enabled","CIS 18.10.42.13.5",STATUS_IMPLEMENTED),
    HardeningItem("WDC-291","Admin Templates","Configure detection for PUAs = Block","CIS 18.10.42.16",STATUS_IMPLEMENTED),
    HardeningItem("WDC-292","Admin Templates","Control exclusions visible to local users = Enabled","CIS 18.10.42.17",STATUS_IMPLEMENTED),
    HardeningItem("WDC-293","Admin Templates","Allow Offer Remote Assistance = Disabled","CIS 18.9.37.1",STATUS_IMPLEMENTED),
    HardeningItem("WDC-294","Admin Templates","Allow Solicited Remote Assistance = Disabled","CIS 18.9.37.2",STATUS_IMPLEMENTED),
    HardeningItem("WDC-295","Admin Templates","Do not allow COM port redirection = Enabled","CIS 18.10.57.3.3.2",STATUS_IMPLEMENTED),
    HardeningItem("WDC-296","Admin Templates","Do not allow drive redirection = Enabled","CIS 18.10.57.3.3.3",STATUS_IMPLEMENTED),
    HardeningItem("WDC-297","Admin Templates","Do not allow location redirection = Enabled","CIS 18.10.57.3.3.4",STATUS_IMPLEMENTED),
    HardeningItem("WDC-298","Admin Templates","Do not allow LPT port redirection = Enabled","CIS 18.10.57.3.3.5",STATUS_IMPLEMENTED),
    HardeningItem("WDC-299","Admin Templates","Do not allow supported PnP device redirection = Enabled","CIS 18.10.57.3.3.6",STATUS_IMPLEMENTED),
    HardeningItem("WDC-300","Admin Templates","Do not allow WebAuthn redirection = Enabled","CIS 18.10.57.3.3.7",STATUS_IMPLEMENTED),
    HardeningItem("WDC-301","Admin Templates","Restrict clipboard transfer from server to client = Enabled","CIS 18.10.57.3.3.8",STATUS_IMPLEMENTED),
    HardeningItem("WDC-302","Admin Templates","Always prompt for password on RDS connection = Enabled","CIS 18.10.57.3.9.1",STATUS_IMPLEMENTED),
    HardeningItem("WDC-303","Admin Templates","Require secure RPC communication = Enabled","CIS 18.10.57.3.9.2",STATUS_IMPLEMENTED),
    HardeningItem("WDC-304","Admin Templates","Require SSL for RDP = SSL","CIS 18.10.57.3.9.3",STATUS_IMPLEMENTED),
    HardeningItem("WDC-305","Admin Templates","Require NLA for remote connections = Enabled","CIS 18.10.57.3.9.4",STATUS_IMPLEMENTED),
    HardeningItem("WDC-306","Admin Templates","Set client connection encryption = High Level","CIS 18.10.57.3.9.5",STATUS_IMPLEMENTED),
    HardeningItem("WDC-307","Admin Templates","Set time limit: active idle RDS = 15 min","CIS 18.10.57.3.10.1",STATUS_IMPLEMENTED),
    HardeningItem("WDC-308","Admin Templates","Set time limit: disconnected sessions = 1 min","CIS 18.10.57.3.10.2",STATUS_IMPLEMENTED),
    HardeningItem("WDC-309","Admin Templates","Prevent downloading of enclosures = Enabled","CIS 18.10.58.1",STATUS_IMPLEMENTED),
    HardeningItem("WDC-310","Admin Templates","Allow Cloud Search = Disable Cloud Search","CIS 18.10.59.2",STATUS_IMPLEMENTED),
    HardeningItem("WDC-311","Admin Templates","Allow indexing of encrypted files = Disabled","CIS 18.10.59.3",STATUS_IMPLEMENTED),
    HardeningItem("WDC-312","Admin Templates","Turn off KMS Client Online AVS Validation = Enabled","CIS 18.10.63.1",STATUS_IMPLEMENTED),
    HardeningItem("WDC-313","Admin Templates","PowerShell: Script Block Logging = Enabled","CIS 18.10.88.1",STATUS_IMPLEMENTED),
    HardeningItem("WDC-314","Admin Templates","PowerShell: Transcription = Enabled","CIS 18.10.88.2",STATUS_IMPLEMENTED),
    HardeningItem("WDC-315","Admin Templates","WinRM Client: Allow Basic auth = Disabled","CIS 18.10.90.1.1",STATUS_IMPLEMENTED),
    HardeningItem("WDC-316","Admin Templates","WinRM Client: Allow unencrypted traffic = Disabled","CIS 18.10.90.1.2",STATUS_IMPLEMENTED),
    HardeningItem("WDC-317","Admin Templates","WinRM Client: Disallow Digest auth = Enabled","CIS 18.10.90.1.3",STATUS_IMPLEMENTED),
    HardeningItem("WDC-318","Admin Templates","WinRM Service: Allow Basic auth = Disabled","CIS 18.10.90.2.1",STATUS_IMPLEMENTED),
    HardeningItem("WDC-319","Admin Templates","WinRM Service: Allow remote server management = Disabled","CIS 18.10.90.2.2",STATUS_IMPLEMENTED),
    HardeningItem("WDC-320","Admin Templates","WinRM Service: Allow unencrypted traffic = Disabled","CIS 18.10.90.2.3",STATUS_IMPLEMENTED),
    HardeningItem("WDC-321","Admin Templates","WinRM Service: Disallow RunAs credentials = Enabled","CIS 18.10.90.2.4",STATUS_IMPLEMENTED),
    HardeningItem("WDC-322","Admin Templates","Windows Remote Shell: Allow Remote Shell Access = Disabled","CIS 18.10.91.1",STATUS_IMPLEMENTED),
    HardeningItem("WDC-323","Admin Templates","Windows Security: Prevent users modifying settings = Enabled","CIS 18.10.93.2.1",STATUS_IMPLEMENTED),
    HardeningItem("WDC-324","Admin Templates","Windows Update: No auto-restart = Disabled","CIS 18.10.94.1.1",STATUS_IMPLEMENTED),
    HardeningItem("WDC-325","Admin Templates","Windows Update: Configure Automatic Updates = Enabled","CIS 18.10.94.2.1",STATUS_IMPLEMENTED),
    HardeningItem("WDC-326","Admin Templates","Windows Update: Scheduled install day = 0 (every day)","CIS 18.10.94.2.2",STATUS_IMPLEMENTED),
    HardeningItem("WDC-327","Admin Templates","Disable WPAD = Enabled","CIS 18.11.1",STATUS_IMPLEMENTED),
    HardeningItem("WDC-328","Admin Templates","Disable proxy auth over loopback = Enabled","CIS 18.11.2",STATUS_IMPLEMENTED),
    HardeningItem("WDC-329","Admin Templates","Allow Windows Ink Workspace = Disabled","CIS 18.10.81.2",STATUS_IMPLEMENTED),
    HardeningItem("WDC-330","Admin Templates","Allow user control over installs = Disabled","CIS 18.10.82.1",STATUS_IMPLEMENTED),
    HardeningItem("WDC-331","Admin Templates","Always install with elevated privileges = Disabled","CIS 18.10.82.2",STATUS_IMPLEMENTED),
    HardeningItem("WDC-332","Admin Templates","Prevent MPR password notifications = Disabled","CIS 18.10.83.1",STATUS_IMPLEMENTED),
    HardeningItem("WDC-333","Admin Templates","Sign-in and lock last user after restart = Disabled","CIS 18.10.83.2",STATUS_IMPLEMENTED),
    HardeningItem("WDC-334","Admin Templates","Allow Microsoft accounts to be optional = Enabled","CIS 18.10.6.1",STATUS_IMPLEMENTED),
    HardeningItem("WDC-335","Admin Templates","Windows Defender SmartScreen = Enabled: Warn and prevent bypass","CIS 18.10.77.2.1",STATUS_IMPLEMENTED),
    HardeningItem("WDC-336","Admin Templates","Turn off location = Enabled","CIS 18.10.36.1",STATUS_IMPLEMENTED),
    HardeningItem("WDC-337","Admin Templates","Allow Message Service Cloud Sync = Disabled","CIS 18.10.40.1",STATUS_IMPLEMENTED),
    HardeningItem("WDC-338","Admin Templates","Turn off Push To Install = Enabled","CIS 18.10.56.1",STATUS_IMPLEMENTED),
    HardeningItem("WDC-339","Admin Templates","Prevent Codec Download = Enabled","CIS 19.7.46.2.1",STATUS_IMPLEMENTED),
    HardeningItem("WDC-340","Admin Templates","Disallow copying user input methods for sign-in = Enabled","CIS 18.9.28.1",STATUS_IMPLEMENTED),
    HardeningItem("WDC-341","ISSP","Fine-grained PSO: Standard users min 12 chars, 90-day expiry","ISSP §7.1",STATUS_IMPLEMENTED),
    HardeningItem("WDC-342","ISSP","Fine-grained PSO: Admin accounts min 18 chars, 60-day expiry","ISSP §7.2",STATUS_IMPLEMENTED),
    HardeningItem("WDC-343","ISSP","Session auto-lock after 300 seconds (5 min)","ISSP §4.2",STATUS_IMPLEMENTED,"Via WDC-069"),
    HardeningItem("WDC-344","ISSP","Emergency local admin (breakglass) account","ISSP §8",STATUS_NOT_IMPLEMENTED,
        "Procedural: passwords must be printed, sealed in envelopes, stored in physical safe. Cannot be automated."),
    HardeningItem("WDC-345","ISSP","Account deactivation on departure (disable 90 days, delete day 91)","ISSP §6",STATUS_NOT_IMPLEMENTED,
        "HR lifecycle process requiring integration with HR system. Cannot be automated without IAM/ITSM."),
    HardeningItem("WDC-346","ISSP","CMDB asset inventory maintenance","ISSP §4",STATUS_NOT_IMPLEMENTED,
        "Organizational process — requires ongoing manual updates. Script generates a point-in-time snapshot only."),
    HardeningItem("WDC-347","ISSP","VPN enforcement for remote access","ISSP §4.2",STATUS_NOT_IMPLEMENTED,
        "Requires VPN gateway infrastructure configuration — out of scope for OS hardening script."),
    HardeningItem("WDC-348","ISSP","BitLocker full disk encryption for laptops","ISSP §5.1",STATUS_IMPLEMENTED),
    HardeningItem("WDC-349","ISSP","Centralized antivirus management","ISSP §5.1",STATUS_NOT_IMPLEMENTED,
        "Requires SCCM/Intune/AV management server. Script enables Windows Defender with hardened settings only."),
    HardeningItem("WDC-350","ISSP","Offsite backup procedure","ISSP §10",STATUS_NOT_IMPLEMENTED,
        "Requires backup infrastructure. Script documents the requirement and checks backup service status."),
    HardeningItem("WDC-351","ISSP","Separate admin accounts from user accounts","ISSP §6",STATUS_NOT_IMPLEMENTED,
        "Organizational naming convention. Script validates and reports but cannot enforce account restructuring."),
]

# Ubuntu client items (UBU-001 … UBU-113) follow the CIS Ubuntu Linux
# Benchmark, supplemented by company ISSP (ISO 27002 v2) controls.
UBUNTU_ITEMS: List[HardeningItem] = [
    # ── Firewall (UFW) ────────────────────────────────────────────────────────
    HardeningItem("UBU-001","Firewall","Install and enable UFW","CIS",STATUS_IMPLEMENTED),
    HardeningItem("UBU-002","Firewall","UFW default deny incoming","CIS",STATUS_IMPLEMENTED),
    HardeningItem("UBU-003","Firewall","UFW default allow outgoing","CIS",STATUS_IMPLEMENTED),
    HardeningItem("UBU-004","Firewall","UFW allow SSH (22/tcp)","CIS",STATUS_IMPLEMENTED),
    HardeningItem("UBU-005","Kernel","sysctl: net.ipv4.ip_forward = 0","CIS",STATUS_IMPLEMENTED),
    HardeningItem("UBU-006","Kernel","sysctl: net.ipv4.conf.all.send_redirects = 0","CIS",STATUS_IMPLEMENTED),
    HardeningItem("UBU-007","Kernel","sysctl: net.ipv4.conf.all.accept_redirects = 0","CIS",STATUS_IMPLEMENTED),
    HardeningItem("UBU-008","Kernel","sysctl: net.ipv4.conf.default.accept_redirects = 0","CIS",STATUS_IMPLEMENTED),
    HardeningItem("UBU-009","Kernel","sysctl: net.ipv4.conf.all.secure_redirects = 0","CIS",STATUS_IMPLEMENTED),
    HardeningItem("UBU-010","Kernel","sysctl: net.ipv4.conf.default.secure_redirects = 0","CIS",STATUS_IMPLEMENTED),
    HardeningItem("UBU-011","Kernel","sysctl: net.ipv4.conf.all.log_martians = 1","CIS",STATUS_IMPLEMENTED),
    HardeningItem("UBU-012","Kernel","sysctl: net.ipv4.tcp_syncookies = 1","CIS",STATUS_IMPLEMENTED),
    HardeningItem("UBU-013","Kernel","sysctl: net.ipv4.icmp_echo_ignore_broadcasts = 1","CIS",STATUS_IMPLEMENTED),
    HardeningItem("UBU-014","Kernel","sysctl: net.ipv4.icmp_ignore_bogus_error_responses = 1","CIS",STATUS_IMPLEMENTED),
    HardeningItem("UBU-015","Kernel","sysctl: net.ipv4.conf.all.rp_filter = 1","CIS",STATUS_IMPLEMENTED),
    HardeningItem("UBU-016","Kernel","sysctl: net.ipv6.conf.all.disable_ipv6 = 1","CIS",STATUS_IMPLEMENTED),
    HardeningItem("UBU-017","Kernel","sysctl: kernel.randomize_va_space = 2 (ASLR)","CIS",STATUS_IMPLEMENTED),
    HardeningItem("UBU-018","Kernel","sysctl: kernel.dmesg_restrict = 1","CIS",STATUS_IMPLEMENTED),
    HardeningItem("UBU-019","Kernel","sysctl: kernel.perf_event_paranoid = 3","CIS",STATUS_IMPLEMENTED),
    HardeningItem("UBU-020","Kernel","sysctl: fs.suid_dumpable = 0","CIS",STATUS_IMPLEMENTED),
    HardeningItem("UBU-021","Kernel","sysctl: net.ipv4.conf.all.accept_source_route = 0","CIS",STATUS_IMPLEMENTED),
    HardeningItem("UBU-022","AppArmor","Enable AppArmor in enforce mode","CIS",STATUS_IMPLEMENTED),
    HardeningItem("UBU-023","AppArmor","Ensure all AppArmor profiles loaded","CIS",STATUS_IMPLEMENTED),
    HardeningItem("UBU-024","SSH","PermitRootLogin = no","CIS",STATUS_IMPLEMENTED),
    HardeningItem("UBU-025","SSH","Protocol = 2 (implied in modern sshd)","CIS",STATUS_IMPLEMENTED),
    HardeningItem("UBU-026","SSH","MaxAuthTries = 3","CIS",STATUS_IMPLEMENTED),
    HardeningItem("UBU-027","SSH","PermitEmptyPasswords = no","CIS",STATUS_IMPLEMENTED),
    HardeningItem("UBU-028","SSH","X11Forwarding = no","CIS",STATUS_IMPLEMENTED),
    HardeningItem("UBU-029","SSH","ClientAliveInterval = 300 (5 min timeout - ISSP)","CIS + ISSP §4.2",STATUS_IMPLEMENTED),
    HardeningItem("UBU-030","SSH","ClientAliveCountMax = 0","CIS",STATUS_IMPLEMENTED),
    HardeningItem("UBU-031","SSH","LoginGraceTime = 60","CIS",STATUS_IMPLEMENTED),
    HardeningItem("UBU-032","SSH","Banner configured with legal warning","CIS + ISSP",STATUS_IMPLEMENTED),
    HardeningItem("UBU-033","SSH","Ciphers = chacha20-poly1305, aes256-gcm, aes128-gcm","CIS",STATUS_IMPLEMENTED),
    HardeningItem("UBU-034","SSH","MACs = hmac-sha2-512-etm, hmac-sha2-256-etm","CIS",STATUS_IMPLEMENTED),
    HardeningItem("UBU-035","SSH","KexAlgorithms = curve25519-sha256, diffie-hellman-group14-sha256+","CIS",STATUS_IMPLEMENTED),
    HardeningItem("UBU-036","SSH","PasswordAuthentication = yes (key-only not forced)","CIS",STATUS_NOT_IMPLEMENTED,
        "Disabling password auth requires SSH keys pre-configured. Would lock out admins without prior key setup."),
    HardeningItem("UBU-037","SSH","AllowGroups/AllowUsers restriction","CIS",STATUS_NOT_IMPLEMENTED,
        "Site-specific: requires knowledge of local user/group structure. Documented as recommended manual step."),
    HardeningItem("UBU-038","PAM","pwquality: minlen=12, dcredit=-1, ucredit=-1, lcredit=-1, ocredit=-1","CIS + ISSP §7.1",STATUS_IMPLEMENTED),
    HardeningItem("UBU-039","PAM","pwquality: maxrepeat = 3","CIS",STATUS_IMPLEMENTED),
    HardeningItem("UBU-040","PAM","Password history = 24 (pam_pwhistory)","CIS",STATUS_IMPLEMENTED),
    HardeningItem("UBU-041","PAM","Account lockout after 5 failures (pam_faillock)","CIS",STATUS_IMPLEMENTED),
    HardeningItem("UBU-042","PAM","Lockout duration = 15 min","CIS",STATUS_IMPLEMENTED),
    HardeningItem("UBU-043","PAM","Unlock after 15 min (fail_interval = 900)","CIS",STATUS_IMPLEMENTED),
    HardeningItem("UBU-044","Login Defs","PASS_MAX_DAYS = 90","CIS + ISSP §7.1",STATUS_IMPLEMENTED),
    HardeningItem("UBU-045","Login Defs","PASS_MIN_DAYS = 1","CIS",STATUS_IMPLEMENTED),
    HardeningItem("UBU-046","Login Defs","PASS_WARN_AGE = 14","CIS",STATUS_IMPLEMENTED),
    HardeningItem("UBU-047","Login Defs","PASS_MIN_LEN = 12","ISSP §7.1",STATUS_IMPLEMENTED),
    HardeningItem("UBU-048","Services","Disable telnet","CIS",STATUS_IMPLEMENTED),
    HardeningItem("UBU-049","Services","Disable ftp (vsftpd)","CIS",STATUS_IMPLEMENTED),
    HardeningItem("UBU-050","Services","Disable rsh, rlogin, rexec","CIS",STATUS_IMPLEMENTED),
    HardeningItem("UBU-051","Services","Disable avahi-daemon","CIS",STATUS_IMPLEMENTED),
    HardeningItem("UBU-052","Services","Disable cups (if not print server)","CIS",STATUS_IMPLEMENTED),
    HardeningItem("UBU-053","Services","Disable isc-dhcp-server","CIS",STATUS_IMPLEMENTED),
    HardeningItem("UBU-054","Services","Disable slapd (LDAP server)","CIS",STATUS_IMPLEMENTED),
    HardeningItem("UBU-055","Services","Disable nfs-server","CIS",STATUS_IMPLEMENTED),
    HardeningItem("UBU-056","Services","Disable rpcbind","CIS",STATUS_IMPLEMENTED),
    HardeningItem("UBU-057","Services","Disable named (DNS server)","CIS",STATUS_IMPLEMENTED),
    HardeningItem("UBU-058","Services","Disable apache2","CIS",STATUS_IMPLEMENTED),
    HardeningItem("UBU-059","Services","Disable dovecot","CIS",STATUS_IMPLEMENTED),
    HardeningItem("UBU-060","Services","Disable smbd/nmbd","CIS",STATUS_NOT_IMPLEMENTED,
        "May be required for Active Directory domain join (Samba/winbind). Skipped to preserve AD connectivity."),
    HardeningItem("UBU-061","Auditd","Install and enable auditd","CIS",STATUS_IMPLEMENTED),
    HardeningItem("UBU-062","Auditd","Audit: time change events","CIS",STATUS_IMPLEMENTED),
    HardeningItem("UBU-063","Auditd","Audit: user/group modification","CIS",STATUS_IMPLEMENTED),
    HardeningItem("UBU-064","Auditd","Audit: network configuration changes","CIS",STATUS_IMPLEMENTED),
    HardeningItem("UBU-065","Auditd","Audit: sudo usage","CIS",STATUS_IMPLEMENTED),
    HardeningItem("UBU-066","Auditd","Audit: file deletions by users","CIS",STATUS_IMPLEMENTED),
    HardeningItem("UBU-067","Auditd","Audit: system call rules (setuid, mount)","CIS",STATUS_IMPLEMENTED),
    HardeningItem("UBU-068","Auditd","Audit: login/logout events (wtmp, btmp, lastlog)","CIS",STATUS_IMPLEMENTED),
    HardeningItem("UBU-069","Auditd","Audit: privileged commands","CIS",STATUS_IMPLEMENTED),
    HardeningItem("UBU-070","Auditd","Auditd: immutable mode (-e 2)","CIS",STATUS_IMPLEMENTED),
    HardeningItem("UBU-071","Auditd","Auditd: max log file size action = keep_logs","CIS",STATUS_IMPLEMENTED),
    HardeningItem("UBU-072","File Perms","/etc/passwd = 644, root:root","CIS",STATUS_IMPLEMENTED),
    HardeningItem("UBU-073","File Perms","/etc/shadow = 640, root:shadow","CIS",STATUS_IMPLEMENTED),
    HardeningItem("UBU-074","File Perms","/etc/group = 644, root:root","CIS",STATUS_IMPLEMENTED),
    HardeningItem("UBU-075","File Perms","/etc/gshadow = 640, root:shadow","CIS",STATUS_IMPLEMENTED),
    HardeningItem("UBU-076","File Perms","/etc/crontab = 600, root:root","CIS",STATUS_IMPLEMENTED),
    HardeningItem("UBU-077","File Perms","/etc/ssh/sshd_config = 600, root:root","CIS",STATUS_IMPLEMENTED),
    HardeningItem("UBU-078","File Perms","Sticky bit on world-writable dirs","CIS",STATUS_IMPLEMENTED),
    HardeningItem("UBU-079","File Perms","No world-writable files (scan + report)","CIS",STATUS_IMPLEMENTED),
    HardeningItem("UBU-080","File Perms","No unowned files (scan + report)","CIS",STATUS_IMPLEMENTED),
    HardeningItem("UBU-081","File Perms","No legacy '+' entries in passwd/shadow/group","CIS",STATUS_IMPLEMENTED),
    HardeningItem("UBU-082","File Perms","No UID 0 accounts except root","CIS",STATUS_IMPLEMENTED),
    HardeningItem("UBU-083","Filesystem","/tmp: nodev,nosuid,noexec mount options","CIS",STATUS_IMPLEMENTED),
    HardeningItem("UBU-084","Filesystem","/dev/shm: nodev,nosuid,noexec","CIS",STATUS_IMPLEMENTED),
    HardeningItem("UBU-085","Filesystem","Disable core dumps (/etc/security/limits.conf)","CIS",STATUS_IMPLEMENTED),
    HardeningItem("UBU-086","Filesystem","GRUB password protection","CIS",STATUS_NOT_IMPLEMENTED,
        "Requires generating password hash interactively. Cannot be automated without exposing plaintext password."),
    HardeningItem("UBU-087","User Accounts","Lock system accounts (daemon, bin, sys, etc.)","CIS",STATUS_IMPLEMENTED),
    HardeningItem("UBU-088","User Accounts","Disable root login on non-console TTYs (/etc/securetty)","CIS",STATUS_IMPLEMENTED),
    HardeningItem("UBU-089","User Accounts","Ensure no accounts with empty passwords","CIS",STATUS_IMPLEMENTED),
    HardeningItem("UBU-090","User Accounts","Default umask = 027 (/etc/bash.bashrc, /etc/profile)","CIS",STATUS_IMPLEMENTED),
    HardeningItem("UBU-091","Cron","Restrict cron to authorized users (cron.allow)","CIS",STATUS_IMPLEMENTED),
    HardeningItem("UBU-092","Cron","Restrict at to authorized users (at.allow)","CIS",STATUS_IMPLEMENTED),
    HardeningItem("UBU-093","Screen Lock","GNOME: lock-delay = 300 seconds (ISSP: 5 min)","ISSP §4.2",STATUS_IMPLEMENTED),
    HardeningItem("UBU-094","Screen Lock","GNOME: lock-enabled = true","ISSP §4.2",STATUS_IMPLEMENTED),
    HardeningItem("UBU-095","Screen Lock","GNOME: idle-delay = 300 seconds","ISSP §4.2",STATUS_IMPLEMENTED),
    HardeningItem("UBU-096","Updates","Install and configure unattended-upgrades","ISSP §5.1",STATUS_IMPLEMENTED),
    HardeningItem("UBU-097","Updates","Enable automatic security updates","ISSP §5.1 + CIS",STATUS_IMPLEMENTED),
    HardeningItem("UBU-098","Integrity","Install AIDE (file integrity monitoring)","CIS",STATUS_IMPLEMENTED),
    HardeningItem("UBU-099","Integrity","AIDE: initialize database","CIS",STATUS_IMPLEMENTED),
    HardeningItem("UBU-100","Integrity","AIDE: daily check cron job","CIS",STATUS_IMPLEMENTED),
    HardeningItem("UBU-101","Logging","rsyslog: log file permissions (640)","CIS",STATUS_IMPLEMENTED),
    HardeningItem("UBU-102","Logging","logrotate: configured","CIS",STATUS_IMPLEMENTED),
    HardeningItem("UBU-103","Logging","NTP/chrony time synchronization","CIS",STATUS_IMPLEMENTED),
    HardeningItem("UBU-104","Logging","Disable Ctrl+Alt+Del reboot","CIS",STATUS_IMPLEMENTED),
    HardeningItem("UBU-105","Banners","/etc/motd: legal warning configured","CIS + ISSP",STATUS_IMPLEMENTED),
    HardeningItem("UBU-106","Banners","/etc/issue: pre-login banner","CIS",STATUS_IMPLEMENTED),
    HardeningItem("UBU-107","Banners","/etc/issue.net: network banner","CIS",STATUS_IMPLEMENTED),
    HardeningItem("UBU-108","Sudo","Sudo: requires password","CIS",STATUS_IMPLEMENTED),
    HardeningItem("UBU-109","Sudo","Sudo: timestamp_timeout = 5 min","CIS",STATUS_IMPLEMENTED),
    HardeningItem("UBU-110","Encryption","Check LUKS encryption status (report if not encrypted)","ISSP §5.1",STATUS_IMPLEMENTED,
        "Script checks and reports. Enabling LUKS on existing system requires full reinstall."),
    HardeningItem("UBU-111","USB","Disable USB storage module (usb-storage)","CIS",STATUS_NOT_IMPLEMENTED,
        "May break legitimate USB use (keyboards, drives). Admin must decide per-machine policy."),
    HardeningItem("UBU-112","ISSP","Session timeout in SSH = 5 min","ISSP §4.2",STATUS_IMPLEMENTED,"Via UBU-029/030"),
    HardeningItem("UBU-113","ISSP","VPN enforcement","ISSP §4.2",STATUS_NOT_IMPLEMENTED,
        "Requires VPN client/gateway infrastructure. Script checks VPN client installation and reports."),
]


# ─── Markdown report ─────────────────────────────────────────────────────────

def _md_table(items: List[HardeningItem]) -> str:
    """
    Render a list of HardeningItems as a GitHub-flavored Markdown table string.

    Args:
        items: Ordered list of hardening controls to tabulate.

    Returns:
        Multi-line string containing the complete Markdown table.
    """
    header    = "| ID | Category | Hardening Point | Source | Status | Reason if Not Implemented |\n"
    separator = "|----|----------|-----------------|--------|--------|---------------------------|\n"
    rows = "".join(
        f"| {item.item_id} | {item.category} | {item.description} "
        f"| {item.source} | {item.status} | {item.reason} |\n"
        for item in items
    )
    return header + separator + rows


def write_markdown(output_path: str,
                   windows_items: Optional[List[HardeningItem]] = None,
                   ubuntu_items:  Optional[List[HardeningItem]] = None) -> None:
    """
    Write the full compliance report as a Markdown file.

    The file contains a legend, a per-OS summary table, and two detailed
    tables (Windows DC and Ubuntu) with one row per hardening control.

    Args:
        output_path:   Absolute path to write the .md file (e.g. project_root/IMPLEMENTATION.md).
        windows_items: Windows DC hardening items; defaults to WINDOWS_DC_ITEMS.
        ubuntu_items:  Ubuntu hardening items; defaults to UBUNTU_ITEMS.
    """
    if windows_items is None:
        windows_items = WINDOWS_DC_ITEMS
    if ubuntu_items is None:
        ubuntu_items = UBUNTU_ITEMS

    # ── Compute per-OS status counts for the summary table ───────────────────
    wdc_total  = len(windows_items)
    wdc_impl   = sum(1 for i in windows_items if i.status == STATUS_IMPLEMENTED)
    wdc_not    = sum(1 for i in windows_items if i.status == STATUS_NOT_IMPLEMENTED)
    wdc_manual = sum(1 for i in windows_items if i.status == STATUS_MANUAL)

    ubu_total  = len(ubuntu_items)
    ubu_impl   = sum(1 for i in ubuntu_items if i.status == STATUS_IMPLEMENTED)
    ubu_not    = sum(1 for i in ubuntu_items if i.status == STATUS_NOT_IMPLEMENTED)
    ubu_manual = sum(1 for i in ubuntu_items if i.status == STATUS_MANUAL)

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    content = f"""# IMPLEMENTATION — AD DC + Ubuntu Hardening

**Company**: Bidouille (automotive sector)
**ISSP**: ISO 27002 v2
**CIS Reference**: CIS Microsoft Windows Server 2025 Benchmark v2.0.0 — Level 1 DC
**Generated**: {now}

## Legend

- **Implemented**: Applied by the script
- **Not Implemented**: Not applied — reason given
- **Manual**: Procedural/organizational — cannot be automated

## Summary

| OS | Total | Implemented | Not Implemented | Manual |
|----|-------|-------------|-----------------|--------|
| Windows DC | {wdc_total} | {wdc_impl} | {wdc_not} | {wdc_manual} |
| Ubuntu | {ubu_total} | {ubu_impl} | {ubu_not} | {ubu_manual} |

---

## Windows DC Hardening (CIS L1 DC + ISSP)

{_md_table(windows_items)}

---

## Ubuntu Client Hardening (CIS Ubuntu + ISSP)

{_md_table(ubuntu_items)}
"""

    try:
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(content)
        log_ok(f"IMPLEMENTATION.md written → {output_path}")
    except OSError as exc:
        log_warn(f"Could not write IMPLEMENTATION.md: {exc}")


# ─── ODS report ──────────────────────────────────────────────────────────────

def write_ods(output_path: str,
              windows_items: Optional[List[HardeningItem]] = None,
              ubuntu_items:  Optional[List[HardeningItem]] = None) -> None:
    """
    Write the compliance data as a color-coded LibreOffice Calc (.ods) file.

    The workbook contains three sheets:
      • "Windows DC"  — all WDC-xxx items
      • "Ubuntu"      — all UBU-xxx items
      • "Summary"     — per-OS row with totals by status

    Row color convention:
      Green  (#C6EFCE) — Implemented
      Red    (#FFC7CE) — Not Implemented
      Yellow (#FFEB9C) — Manual

    If the odfpy library is not installed the function logs a warning and
    returns without raising an exception, so the overall hardening run is
    not aborted just because the spreadsheet cannot be generated.

    Args:
        output_path:   Absolute path to write the .ods file.
        windows_items: Windows DC hardening items; defaults to WINDOWS_DC_ITEMS.
        ubuntu_items:  Ubuntu hardening items; defaults to UBUNTU_ITEMS.
    """
    if not _ODF_AVAILABLE:
        # odfpy failed to import at module load time — skip gracefully.
        log_warn("odfpy not installed — skipping ODS generation.  Run: pip install odfpy")
        return

    if windows_items is None:
        windows_items = WINDOWS_DC_ITEMS
    if ubuntu_items is None:
        ubuntu_items = UBUNTU_ITEMS

    doc = OpenDocumentSpreadsheet()

    # ── Cell style factory ────────────────────────────────────────────────────
    # Each style is registered once in the document's automatic-styles section.
    # The function returns the style *name* (a string) passed to
    # TableCell(stylename=...) when building rows.
    def _make_style(name: str, bg_color: str, bold: bool = False) -> str:
        st = Style(name=name, family="table-cell")
        # Background fill + thin border on every cell edge
        st.addElement(TableCellProperties(
            backgroundcolor=bg_color,
            border="0.05pt solid #000000"
        ))
        # Font weight (header row is bold, data rows are normal)
        st.addElement(TextProperties(fontweight="bold" if bold else "normal"))
        doc.automaticstyles.addElement(st)
        return name

    # Register all styles used across all sheets
    style_header      = _make_style("header_style",  "#4472C4", bold=True)  # dark-blue header
    style_implemented = _make_style("impl_style",    "#C6EFCE")             # light green
    style_not_impl    = _make_style("notimpl_style", "#FFC7CE")             # light red
    style_manual      = _make_style("manual_style",  "#FFEB9C")             # light yellow
    style_default     = _make_style("default_style", "#FFFFFF")             # white (summary rows)

    # ── Cell / row helpers ────────────────────────────────────────────────────

    def _cell(text, stylename: Optional[str] = None) -> TableCell:
        """Create a single string-typed ODS table cell with optional style."""
        tc = TableCell(
            stylename=stylename if stylename else "",
            valuetype="string"
        )
        tc.addElement(P(text=str(text) if text is not None else ""))
        return tc

    def _header_row(table: Table, columns: List[str]) -> None:
        """Append a bold header row to *table*."""
        tr = TableRow()
        for col in columns:
            tr.addElement(_cell(col, style_header))
        table.addElement(tr)

    def _data_row(table: Table, item: HardeningItem) -> None:
        """Append a color-coded data row for *item* to *table*."""
        # Pick background color based on implementation status
        if item.status == STATUS_IMPLEMENTED:
            row_style = style_implemented
        elif item.status == STATUS_NOT_IMPLEMENTED:
            row_style = style_not_impl
        elif item.status == STATUS_MANUAL:
            row_style = style_manual
        else:
            row_style = style_default  # unknown status — white

        tr = TableRow()
        for val in [item.item_id, item.category, item.description,
                    item.source, item.status, item.reason]:
            tr.addElement(_cell(val, row_style))
        table.addElement(tr)

    COLUMNS = ["ID", "Category", "Hardening Point", "Source", "Status",
               "Reason if Not Implemented"]

    # ── Sheet 1: Windows DC ───────────────────────────────────────────────────
    sheet_win = Table(name="Windows DC")
    _header_row(sheet_win, COLUMNS)
    for item in windows_items:
        _data_row(sheet_win, item)
    doc.spreadsheet.addElement(sheet_win)

    # ── Sheet 2: Ubuntu ───────────────────────────────────────────────────────
    sheet_ubu = Table(name="Ubuntu")
    _header_row(sheet_ubu, COLUMNS)
    for item in ubuntu_items:
        _data_row(sheet_ubu, item)
    doc.spreadsheet.addElement(sheet_ubu)

    # ── Sheet 3: Summary ──────────────────────────────────────────────────────
    sheet_sum = Table(name="Summary")
    _header_row(sheet_sum, ["OS", "Total", "Implemented", "Not Implemented", "Manual"])
    for label, items in [("Windows DC", windows_items), ("Ubuntu", ubuntu_items)]:
        total    = len(items)
        impl     = sum(1 for i in items if i.status == STATUS_IMPLEMENTED)
        not_impl = sum(1 for i in items if i.status == STATUS_NOT_IMPLEMENTED)
        manual   = sum(1 for i in items if i.status == STATUS_MANUAL)
        tr = TableRow()
        for val in [label, total, impl, not_impl, manual]:
            tr.addElement(_cell(val, style_default))
        sheet_sum.addElement(tr)
    doc.spreadsheet.addElement(sheet_sum)

    # ── Save to disk ──────────────────────────────────────────────────────────
    try:
        doc.save(output_path)
        log_ok(f"IMPLEMENTATION.ods written → {output_path}")
    except OSError as exc:
        log_warn(f"Could not write IMPLEMENTATION.ods: {exc}")


# ─── Public entry point ───────────────────────────────────────────────────────

def generate_reports(project_root: str,
                     windows_items: Optional[List[HardeningItem]] = None,
                     ubuntu_items:  Optional[List[HardeningItem]] = None) -> None:
    """
    Generate both compliance reports (Markdown + ODS) in the project root.

    This is the single function called by harden.py at the end of every run
    and by --report-only mode.  Both output paths are derived from
    *project_root* so callers don't need to know the file names.

    Args:
        project_root:  Root directory of the hardening project (where harden.py lives).
        windows_items: Optional override for the Windows DC item list.
        ubuntu_items:  Optional override for the Ubuntu item list.
    """
    md_path  = os.path.join(project_root, "IMPLEMENTATION.md")
    ods_path = os.path.join(project_root, "IMPLEMENTATION.ods")
    write_markdown(md_path,  windows_items, ubuntu_items)
    write_ods(ods_path,      windows_items, ubuntu_items)
