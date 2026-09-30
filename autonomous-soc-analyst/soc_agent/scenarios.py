"""Built-in attack scenarios for the simulator, each in its SIEM's native payload format."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from .connectors.mock import (
    ADMIN_TOOL,
    ATTACKER_IP,
    C2_LOCKBIT,
    DEVICES,
    LOCKBIT,
    MIMIKATZ,
    QAKBOT,
    UNKNOWN_BIN,
)


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _uid(name: str) -> str:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S%f")
    return f"sim-{name}-{stamp}"


def ransomware_defender() -> tuple[str, dict[str, Any]]:
    """Defender XDR (Graph alerts_v2): LockBit on a finance workstation."""
    dev = DEVICES["ws-fin-042"]
    return "defender", {
        "id": _uid("ransomware"),
        "title": "Ransomware behavior detected in the file system",
        "description": "LockBit-style mass file encryption and ransom note creation on WS-FIN-042.",
        "severity": "high",
        "category": "Ransomware",
        "detectionSource": "microsoftDefenderForEndpoint",
        "serviceSource": "microsoftDefenderForEndpoint",
        "mitreTechniques": ["T1486", "T1490"],
        "createdDateTime": _now(),
        "evidence": [
            {"@odata.type": "#microsoft.graph.security.deviceEvidence", "deviceDnsName": dev.hostname,
             "mdeDeviceId": dev.mde_id, "osPlatform": "Windows11"},
            {"@odata.type": "#microsoft.graph.security.processEvidence",
             "imageFile": {"fileName": LOCKBIT.name, "filePath": LOCKBIT.path, "sha256": LOCKBIT.sha256},
             "userAccount": {"accountName": "jdoe", "domainName": "CONTOSO",
                             "userPrincipalName": "jdoe@contoso.com"}},
            {"@odata.type": "#microsoft.graph.security.ipEvidence", "ipAddress": C2_LOCKBIT},
        ],
    }


def commodity_malware_mde() -> tuple[str, dict[str, Any]]:
    """Legacy Defender for Endpoint /api/alerts format: QakBot loader from a phishing download."""
    dev = DEVICES["ws-eng-017"]
    return "defender", {
        "id": _uid("qakbot"),
        "title": "'QakBot' malware was detected",
        "description": "Trojan:Win32/Qakbot executed from the Downloads folder.",
        "severity": "High",
        "category": "Malware",
        "detectionSource": "WindowsDefenderAv",
        "machineId": dev.mde_id,
        "computerDnsName": dev.hostname,
        "alertCreationTime": _now(),
        "relatedUser": {"userName": "asmith", "domainName": "CONTOSO"},
        "evidence": [
            {"entityType": "File", "fileName": QAKBOT.name, "filePath": QAKBOT.path, "sha256": QAKBOT.sha256},
            {"entityType": "User", "accountName": "asmith", "domainName": "CONTOSO",
             "userPrincipalName": "asmith@contoso.com"},
        ],
    }


def false_positive_sentinel() -> tuple[str, dict[str, Any]]:
    """Sentinel SecurityAlert: PUA detection on the IT department's own signed admin tool."""
    return "sentinel", {
        "SystemAlertId": _uid("pua-fp"),
        "DisplayName": "'AdminToolkit' potentially unwanted application was detected",
        "Description": "A potentially unwanted application was detected on WS-ENG-017.",
        "Severity": "Medium",
        "Category": "Malware",
        "ProductName": "Microsoft Defender Antivirus",
        "TimeGenerated": _now(),
        "Entities": [
            {"Type": "host", "HostName": "ws-eng-017", "DnsDomain": "contoso.com"},
            {"Type": "account", "Name": "asmith", "UPNSuffix": "contoso.com", "NTDomain": "CONTOSO"},
            {"Type": "file", "Name": ADMIN_TOOL.name,
             "FileHashes": [{"Algorithm": "SHA256", "Value": ADMIN_TOOL.sha256}]},
        ],
    }


def impossible_travel_splunk() -> tuple[str, dict[str, Any]]:
    """Splunk ES notable via webhook: account takeover of a sales user."""
    return "splunk", {
        "sid": _uid("travel"),
        "search_name": "Identity - Impossible Travel - Rule",
        "result": {
            "signature": "Impossible travel activity for mchen@contoso.com",
            "description": "Successful sign-ins from the US and Russia 40 minutes apart after a password spray.",
            "user": "mchen@contoso.com",
            "src": ATTACKER_IP,
            "urgency": "medium",
            "annotations.mitre_attack": "T1078, T1110.003",
            "_time": _now(),
        },
    }


def privileged_takeover_sentinel() -> tuple[str, dict[str, Any]]:
    """Sentinel incident (automation-rule / Logic App payload): Global Admin sign-in anomaly."""
    return "sentinel", {
        "object": {
            "name": _uid("admin-takeover"),
            "properties": {
                "title": "Suspicious sign-in: atypical travel for a privileged account",
                "description": "admin.kpatel@contoso.com signed in from Moscow after a password spray.",
                "severity": "High",
                "incidentNumber": 4211,
                "createdTimeUtc": _now(),
                "additionalData": {"alertProductNames": ["Microsoft Entra ID Protection"],
                                   "tactics": ["InitialAccess"], "techniques": ["T1078"]},
                "relatedEntities": [
                    {"kind": "Account", "properties": {"accountName": "admin.kpatel", "upnSuffix": "contoso.com"}},
                    {"kind": "Ip", "properties": {"address": ATTACKER_IP}},
                ],
            },
        }
    }


def domain_controller_generic() -> tuple[str, dict[str, Any]]:
    """Any SIEM, generic schema: credential dumping tool on a domain controller."""
    return "generic", {
        "id": _uid("dc-mimikatz"),
        "source": "qradar",
        "title": "Credential dumping tool (Mimikatz variant) executed on DC01",
        "description": "LSASS memory access by an unsigned binary in C:\\Windows\\Temp.",
        "severity": 8,
        "category": "CredentialAccess",
        "mitre_techniques": ["T1003.001"],
        "devices": [{"hostname": "dc01.contoso.com"}],
        "users": [{"upn": "svc-backup@contoso.com"}],
        "files": [{"name": MIMIKATZ.name, "path": MIMIKATZ.path, "sha256": MIMIKATZ.sha256}],
    }


def unknown_binary_generic() -> tuple[str, dict[str, Any]]:
    """Any SIEM, generic schema: an unsigned binary nobody has seen before."""
    return "generic", {
        "id": _uid("unknown-bin"),
        "source": "elastic",
        "title": "Suspicious process execution from ProgramData",
        "severity": "medium",
        "devices": ["ws-eng-017"],
        "users": ["asmith@contoso.com"],
        "files": [{"name": UNKNOWN_BIN.name, "path": UNKNOWN_BIN.path, "sha256": UNKNOWN_BIN.sha256}],
    }


SCENARIOS = {
    "ransomware": ransomware_defender,
    "malware": commodity_malware_mde,
    "false-positive": false_positive_sentinel,
    "impossible-travel": impossible_travel_splunk,
    "privileged-account": privileged_takeover_sentinel,
    "domain-controller": domain_controller_generic,
    "unknown-binary": unknown_binary_generic,
}
