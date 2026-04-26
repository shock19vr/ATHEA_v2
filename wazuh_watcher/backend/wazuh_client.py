

import os
import logging
from datetime import datetime, timezone, timedelta
from typing import Any

import httpx
from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger(__name__)


INDEXER_URL       = os.getenv("WAZUH_INDEXER_URL")
INDEXER_USER      = os.getenv("WAZUH_INDEXER_USER", "admin")
INDEXER_PASSWORD  = os.getenv("WAZUH_INDEXER_PASSWORD", "")
LEVEL_THRESHOLD   = int(os.getenv("ALERT_LEVEL_THRESHOLD", "2"))
FETCH_LIMIT       = int(os.getenv("ALERT_FETCH_LIMIT", "500"))

INDEX_PATTERN = os.getenv("WAZUH_INDEX_PATTERN", "wazuh-alerts-*")



def _build_query(minutes_back: int = 60) -> dict:
    since = (datetime.now(timezone.utc) - timedelta(minutes=minutes_back)).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )
    return {
        "size": FETCH_LIMIT,
        "sort": [{"timestamp": {"order": "desc"}}],
        "query": {
            "bool": {
                "filter": [
                    {"range": {"timestamp": {"gte": since}}},
                    {"range": {"rule.level": {"gte": LEVEL_THRESHOLD}}},
                ]
            }
        },
        "_source": [
            "timestamp",
            "rule.id",
            "rule.level",
            "rule.description",
            "rule.mitre.id",
            "rule.mitre.tactic",
            "rule.mitre.technique",
            "rule.groups",
            "agent.id",
            "agent.name",
            "agent.ip",
            "manager.name",
            "data.win.system.eventID",
            "data.win.system.computer",
            "data.win.system.channel",
            "data.win.system.processID",
            "data.win.system.providerName",
            "data.win.eventdata.targetUserName",
            "data.win.eventdata.subjectUserName",
            "data.win.eventdata.commandLine",
            "data.win.eventdata.parentCommandLine",
            "data.win.eventdata.ipAddress",
            "data.win.eventdata.ipPort",
            "full_log",
            "location",
            "decoder.name",
            "id",
            "_id",
        ],
    }


def _flatten_hit(hit: dict) -> dict:
    src: dict = hit.get("_source", {})

    def dig(d: dict, *keys: str, default: Any = None) -> Any:
        cur = d
        for k in keys:
            if not isinstance(cur, dict):
                return default
            cur = cur.get(k, default)
            if cur is None:
                return default
        return cur

    doc = {
        "doc_id":           hit.get("_id", ""),
        "timestamp":        src.get("timestamp", ""),
        "rule_id":          str(dig(src, "rule", "id", default="")),
        "rule_level":       int(dig(src, "rule", "level", default=0)),
        "rule_description": dig(src, "rule", "description", default=""),
        "rule_groups":      dig(src, "rule", "groups", default=[]),
        "mitre_ids":        dig(src, "rule", "mitre", "id", default=[]),
        "mitre_tactics":    dig(src, "rule", "mitre", "tactic", default=[]),
        "mitre_techniques": dig(src, "rule", "mitre", "technique", default=[]),
        "agent_id":         dig(src, "agent", "id", default=""),
        "agent_name":       dig(src, "agent", "name", default="unknown"),
        "agent_ip":         dig(src, "agent", "ip", default=""),
        "manager_name":     dig(src, "manager", "name", default=""),
        "event_id":         str(dig(src, "data", "win", "system", "eventID", default="")),
        "computer":         dig(src, "data", "win", "system", "computer", default=""),
        "channel":          dig(src, "data", "win", "system", "channel", default=""),
        "process_id":       dig(src, "data", "win", "system", "processID", default=""),
        "provider_name":    dig(src, "data", "win", "system", "providerName", default=""),
        "target_user":      dig(src, "data", "win", "eventdata", "targetUserName", default=""),
        "subject_user":     dig(src, "data", "win", "eventdata", "subjectUserName", default=""),
        "command_line":     dig(src, "data", "win", "eventdata", "commandLine", default=""),
        "parent_cmd":       dig(src, "data", "win", "eventdata", "parentCommandLine", default=""),
        "src_ip":           dig(src, "data", "win", "eventdata", "ipAddress", default=""),
        "src_port":         dig(src, "data", "win", "eventdata", "ipPort", default=""),
        "full_log":         src.get("full_log", ""),
        "location":         src.get("location", ""),
        "decoder_name":     dig(src, "decoder", "name", default=""),
    }


    for list_field in ("rule_groups", "mitre_ids", "mitre_tactics", "mitre_techniques"):
        if isinstance(doc[list_field], str):
            doc[list_field] = [doc[list_field]] if doc[list_field] else []

    return doc




async def fetch_alerts(minutes_back: int = 60) -> list[dict]:
    url = f"{INDEXER_URL}/{INDEX_PATTERN}/_search"
    query = _build_query(minutes_back=minutes_back)

    try:
        async with httpx.AsyncClient(
            verify=False,
            timeout=30.0,
            auth=(INDEXER_USER, INDEXER_PASSWORD),
        ) as client:
            response = await client.post(url, json=query)
            response.raise_for_status()

        data = response.json()
        hits = data.get("hits", {}).get("hits", [])
        logger.info(f"Wazuh Indexer returned {len(hits)} alerts (last {minutes_back}m, level>={LEVEL_THRESHOLD})")

        alerts = [_flatten_hit(h) for h in hits]
        return alerts

    except httpx.ConnectError as e:
        logger.error(f"Cannot reach Wazuh Indexer at {INDEXER_URL}: {e}")
        raise
    except httpx.HTTPStatusError as e:
        logger.error(f"Wazuh Indexer HTTP error {e.response.status_code}: {e.response.text[:500]}")
        raise
    except Exception as e:
        logger.error(f"Unexpected error fetching alerts: {e}")
        raise


async def test_connection() -> dict:
    try:
        async with httpx.AsyncClient(
            verify=False,
            timeout=10.0,
            auth=(INDEXER_USER, INDEXER_PASSWORD),
        ) as client:
            resp = await client.get(f"{INDEXER_URL}/_cluster/health")
            resp.raise_for_status()
            health = resp.json()
            return {
                "connected": True,
                "cluster_name": health.get("cluster_name", "unknown"),
                "status": health.get("status", "unknown"),
                "indexer_url": INDEXER_URL,
            }
    except Exception as e:
        return {
            "connected": False,
            "error": str(e),
            "indexer_url": INDEXER_URL,
        }
