

import math
import re
import logging
from collections import deque, Counter
from datetime import datetime, timezone
from typing import Optional

import numpy as np
import pandas as pd
import os

logger = logging.getLogger(__name__)

ROLLING_WINDOW_MAX_SIZE = int(os.getenv("ROLLING_WINDOW_MAX_SIZE", "2000"))
FEATURE_WINDOW_SECONDS = float(os.getenv("FEATURE_WINDOW_SECONDS", "60.0"))

EVENTID_THREAT_TIER: dict[str, int] = {
    "4625": 3,
    "4648": 2,
    "4776": 2,
    "4768": 1,
    "4769": 1,
    "4771": 2,
    "4672": 2,
    "4673": 2,
    "4674": 2,
    "4720": 2,
    "4722": 1,
    "4724": 2,
    "4728": 2,
    "4732": 2,
    "4756": 2,
    "4688": 3,
    "4689": 1,
    "1":    3,
    "10":   3,
    "8":    3,
    "25":   3,
    "3":    2,
    "5156": 1,
    "5157": 2,
    "4698": 3,
    "4699": 2,
    "4702": 2,
    "4697": 3,
    "1102": 3,
    "104":  3,
    "4657": 2,
    "13":   2,
    "4663": 2,
    "4624": 0,
    "4634": 0,
    "4647": 0,
    "11":   1,
    "23":   2,
    "4104": 3,
    "4103": 2,
}

_FAILED_LOGIN_IDS    = {"4625", "4771", "529", "530", "531", "532", "533", "534", "535", "539"}
_PROCESS_CREATE_IDS  = {"4688", "1"}
_NETWORK_CONN_IDS    = {"3", "5156", "5157", "5158"}
_PRIVILEGE_USE_IDS   = {"4672", "4673", "4674"}
_SCHEDULED_TASK_IDS  = {"4698", "4699", "4702"}
_LOG_CLEAR_IDS       = {"1102", "104"}
_SERVICE_INSTALL_IDS = {"4697", "7045"}
_LATERAL_MOVE_IDS    = {"4624", "4648", "4776"}
_REG_MODIFY_IDS      = {"13", "4657", "4663"}
_POWERSHELL_IDS      = {"4104", "4103", "400", "403"}

_RULE_GROUP_THREATS = {
    "authentication_failed": "IsFailedLogin",
    "authentication_failures": "IsFailedLogin",
    "brute_force": "IsFailedLogin",
    "privilege_escalation": "IsPrivilegeUse",
    "rootkit": "IsPrivilegeUse",
    "web_attack": "IsNetworkConnection",
    "attack": "IsNetworkConnection",
    "exploit": "IsProcessCreation",
    "malware": "IsProcessCreation",
    "ransomware": "IsProcessCreation",
}

# MITRE tactic severity weights
MITRE_TACTIC_WEIGHT: dict[str, float] = {
    "initial-access":        0.6,
    "execution":             0.8,
    "persistence":           0.9,
    "privilege-escalation":  0.9,
    "defense-evasion":       1.0,
    "credential-access":     0.9,
    "discovery":             0.4,
    "lateral-movement":      0.9,
    "collection":            0.7,
    "exfiltration":          1.0,
    "command-and-control":   0.9,
    "impact":                1.0,
    "reconnaissance":        0.5,
    "resource-development":  0.5,
}

# Suspicious text patterns (for log entropy / shellcode detection)
_RE_POWERSHELL  = re.compile(r"powershell|pwsh|PSExecutionPolicy|EncodedCommand", re.I)
_RE_BASE64      = re.compile(r"(?:[A-Za-z0-9+/]{40,}={0,2})")
_RE_SUSPICIOUS  = re.compile(
    r"mimikatz|sekurlsa|lsadump|invoke-expression|iex\(|"
    r"bypass|downloadstring|webclient|shellcode|mshta|"
    r"regsvr32|rundll32|certutil|bitsadmin|wscript|cscript|"
    r"net\s+user|net\s+localgroup|whoami|ipconfig|netstat",
    re.I
)

class _RollingWindow:
    MAX_SIZE = ROLLING_WINDOW_MAX_SIZE

    def __init__(self):
        self._events: deque[dict] = deque(maxlen=self.MAX_SIZE)

    def add_batch(self, alerts: list[dict]):
        for a in alerts:
            self._events.append({
                "ts":         _parse_ts(a.get("timestamp", "")),
                "agent":      a.get("agent_name", "unknown"),
                "event_id":   a.get("event_id", ""),
                "rule_level": a.get("rule_level", 0),
                "is_failed":  a.get("event_id", "") in _FAILED_LOGIN_IDS,
            })

    def events_in_window(self, agent: str, ref_ts: float, window_sec: float = FEATURE_WINDOW_SECONDS) -> list[dict]:
        cutoff = ref_ts - window_sec
        return [e for e in self._events if e["agent"] == agent and cutoff <= e["ts"] <= ref_ts]


_ROLLING_WINDOW = _RollingWindow()


def _parse_ts(ts_str: str) -> float:
    if not ts_str:
        return 0.0
    try:
        dt = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
        return dt.timestamp()
    except Exception:
        pass
    try:
        return float(ts_str)
    except Exception:
        return 0.0


def _shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    freq = Counter(text)
    length = len(text)
    return -sum((c / length) * math.log2(c / length) for c in freq.values())


def _safe_int(val) -> int:
    try:
        return int(val)
    except Exception:
        return 0


class WazuhFeatureEngineer:

    FEATURE_COLUMNS = [
        "Hour", "IsNightTime", "HourSin", "HourCos",
        "DayOfWeek", "IsWeekend", "TimeSincePrevEvent",
        "RuleLevel", "RuleLevelNorm",
        "EventIDThreatTier", "EventIDFrequency", "EventIDRarity",
        "IsFailedLogin", "IsProcessCreation", "IsNetworkConnection",
        "IsPrivilegeUse", "IsScheduledTask", "IsLogCleared",
        "IsServiceInstall", "IsLateralMove", "IsRegistryMod",
        "IsPowerShell",
        "ComputerEventCount",
        "MitrePresent", "MitreTacticWeight", "MitreTacticCount",
        "EventsPerMinute", "UniqueEventIDsInWindow", "FailedLoginRatio",
        "HighSeverityRatio",
        "CommandLineLength", "LogLength",
        "LogHasPowerShell", "LogHasBase64", "LogHasSuspicious",
        "LogEntropy", "CommandLineEntropy",
    ]

    def extract_features(self, alerts: list[dict]) -> pd.DataFrame:
        if not alerts:
            return pd.DataFrame(columns=self.FEATURE_COLUMNS)

        alerts_sorted = sorted(alerts, key=lambda a: _parse_ts(a.get("timestamp", "")))

        event_id_counts = Counter(a.get("event_id", "") for a in alerts_sorted)
        agent_counts    = Counter(a.get("agent_name", "") for a in alerts_sorted)
        total           = len(alerts_sorted)

        _ROLLING_WINDOW.add_batch(alerts_sorted)

        rows = []
        prev_ts: dict[str, float] = {}

        for alert in alerts_sorted:
            row = self._extract_one(
                alert,
                event_id_counts=event_id_counts,
                agent_counts=agent_counts,
                total=total,
                prev_ts=prev_ts,
            )
            rows.append(row)

        df = pd.DataFrame(rows, columns=self.FEATURE_COLUMNS)

        df = pd.DataFrame(rows, columns=self.FEATURE_COLUMNS)
        df = df.fillna(0.0).astype(float)
        logger.debug(f"Feature extraction complete: {df.shape}")
        return df

    def _extract_one(
        self,
        alert: dict,
        event_id_counts: Counter,
        agent_counts: Counter,
        total: int,
        prev_ts: dict,
    ) -> list:
        ts = _parse_ts(alert.get("timestamp", ""))
        if ts > 0:
            dt = datetime.fromtimestamp(ts, tz=timezone.utc)
            hour       = float(dt.hour)
            day_of_week= float(dt.weekday())
        else:
            hour = day_of_week = 0.0

        is_night    = float(hour < 6 or hour >= 22)
        hour_sin    = math.sin(2 * math.pi * hour / 24.0)
        hour_cos    = math.cos(2 * math.pi * hour / 24.0)
        is_weekend  = float(day_of_week >= 5)

        agent = alert.get("agent_name", "unknown")
        time_since_prev = 0.0
        if agent in prev_ts and prev_ts[agent] > 0 and ts > 0:
            time_since_prev = min(ts - prev_ts[agent], 3600.0)
        if ts > 0:
            prev_ts[agent] = ts

        rule_level      = float(_safe_int(alert.get("rule_level", 0)))
        rule_level_norm = rule_level / 15.0


        eid = str(alert.get("event_id", "")).strip()
        threat_tier     = float(EVENTID_THREAT_TIER.get(eid, 0))
        eid_count       = float(event_id_counts.get(eid, 1))
        eid_freq        = eid_count / max(total, 1)
        eid_rarity      = 1.0 / (eid_freq + 1.0)


        is_failed_login   = float(eid in _FAILED_LOGIN_IDS)
        is_process_create = float(eid in _PROCESS_CREATE_IDS)
        is_network_conn   = float(eid in _NETWORK_CONN_IDS)
        is_privilege_use  = float(eid in _PRIVILEGE_USE_IDS)
        is_sched_task     = float(eid in _SCHEDULED_TASK_IDS)
        is_log_cleared    = float(eid in _LOG_CLEAR_IDS)
        is_service_install= float(eid in _SERVICE_INSTALL_IDS)
        is_lateral_move   = float(eid in _LATERAL_MOVE_IDS)
        is_reg_mod        = float(eid in _REG_MODIFY_IDS)
        is_powershell_eid = float(eid in _POWERSHELL_IDS)


        rule_groups = [g.lower() for g in alert.get("rule_groups", [])]
        for keyword, flag in _RULE_GROUP_THREATS.items():
            if any(keyword in g for g in rule_groups):
                if flag == "IsFailedLogin":    is_failed_login   = 1.0
                if flag == "IsPrivilegeUse":   is_privilege_use  = 1.0
                if flag == "IsNetworkConnection": is_network_conn= 1.0
                if flag == "IsProcessCreation": is_process_create= 1.0


        computer_event_count = float(agent_counts.get(agent, 1))


        mitre_ids     = alert.get("mitre_ids", [])
        mitre_tactics = [t.lower() for t in alert.get("mitre_tactics", [])]
        mitre_present = float(len(mitre_ids) > 0)
        mitre_tactic_weight = max(
            (MITRE_TACTIC_WEIGHT.get(t, 0.0) for t in mitre_tactics),
            default=0.0
        )
        mitre_tactic_count = float(len(mitre_tactics))


        if ts > 0:
            window_events = _ROLLING_WINDOW.events_in_window(agent, ts, window_sec=FEATURE_WINDOW_SECONDS)
        else:
            window_events = []

        events_per_minute   = float(len(window_events))
        unique_eids_window  = float(len(set(e["event_id"] for e in window_events)))
        n_failed_in_window  = float(sum(1 for e in window_events if e["is_failed"]))
        failed_login_ratio  = n_failed_in_window / max(events_per_minute, 1.0)
        n_high_sev_window   = float(sum(1 for e in window_events if e["rule_level"] >= 10))
        high_sev_ratio      = n_high_sev_window / max(events_per_minute, 1.0)


        cmd_line   = str(alert.get("command_line", "") or "")
        full_log   = str(alert.get("full_log", "") or alert.get("rule_description", "") or "")

        cmd_len    = float(len(cmd_line))
        log_len    = float(len(full_log))


        search_text = f"{cmd_line} {full_log} {alert.get('parent_cmd', '')}"
        has_ps      = float(bool(_RE_POWERSHELL.search(search_text)))
        has_b64     = float(bool(_RE_BASE64.search(search_text)))
        has_susp    = float(bool(_RE_SUSPICIOUS.search(search_text)))


        has_ps = max(has_ps, is_powershell_eid)

        log_entropy = _shannon_entropy(full_log[:2000])
        cmd_entropy = _shannon_entropy(cmd_line[:500])


        return [
            hour, is_night, hour_sin, hour_cos,
            day_of_week, is_weekend, time_since_prev,
            rule_level, rule_level_norm,
            threat_tier, eid_freq, eid_rarity,
            is_failed_login, is_process_create, is_network_conn,
            is_privilege_use, is_sched_task, is_log_cleared,
            is_service_install, is_lateral_move, is_reg_mod,
            is_powershell_eid,
            computer_event_count,
            mitre_present, mitre_tactic_weight, mitre_tactic_count,
            events_per_minute, unique_eids_window, failed_login_ratio,
            high_sev_ratio,
            cmd_len, log_len,
            has_ps, has_b64, has_susp,
            log_entropy, cmd_entropy,
        ]
