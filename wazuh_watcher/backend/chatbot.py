"""
chatbot.py — Gemini-powered security analyst chatbot for Wazuh-ATHEA.

The chatbot receives the live pipeline snapshot (anomalies, normal alerts,
SHAP explanations, MITRE stages, cluster IDs) and answers analyst questions
by correlating anomalous vs normal behaviour.
"""

import logging
import os
from typing import Any

import google.generativeai as genai
from dotenv import load_dotenv
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

load_dotenv()

logger = logging.getLogger(__name__)

# ── Gemini configuration ────────────────────────────────────────────────────
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")
GEMINI_MODEL   = os.getenv("GEMINI_MODEL", "gemini-2.5-flash-preview-04-17")

if GEMINI_API_KEY and GEMINI_API_KEY != "your_gemini_api_key_here":
    genai.configure(api_key=GEMINI_API_KEY)
    _gemini_ready = True
else:
    logger.warning("GEMINI_API_KEY not configured — chatbot will return placeholder responses.")
    _gemini_ready = False


# ── Request / Response models ───────────────────────────────────────────────
class ChatMessage(BaseModel):
    role: str    # "user" or "model"
    content: str


class ChatRequest(BaseModel):
    message: str
    history: list[ChatMessage] = []


class ChatResponse(BaseModel):
    reply: str
    model: str
    context_loaded: bool


# ── Feature name → human-readable description ───────────────────────────────
_FEATURE_DESCRIPTIONS: dict[str, str] = {
    "IsFailedLogin":        "failed authentication attempt",
    "IsProcessCreation":    "process creation event",
    "IsNetworkConnection":  "network connection event",
    "IsPrivilegeUse":       "privilege use / escalation",
    "IsScheduledTask":      "scheduled task creation/modification",
    "IsLogCleared":         "security log cleared (defense evasion)",
    "IsServiceInstall":     "service installation (persistence)",
    "IsLateralMove":        "lateral movement indicator",
    "IsRegistryMod":        "registry modification",
    "IsPowerShell":         "PowerShell activity",
    "LogHasSuspicious":     "suspicious keywords (mimikatz/bypass/shellcode/etc.)",
    "LogHasBase64":         "base64-encoded content in log",
    "LogHasPowerShell":     "PowerShell strings in log text",
    "IsNightTime":          "occurred during off-hours (before 6AM or after 10PM)",
    "IsWeekend":            "occurred on a weekend",
    "FailedLoginRatio":     "ratio of failed logins in the rolling time window",
    "HighSeverityRatio":    "ratio of high-severity (level ≥10) events in the window",
    "EventsPerMinute":      "event frequency in the rolling window",
    "UniqueEventIDsInWindow":"variety of different Event IDs in the rolling window",
    "TimeSincePrevEvent":   "time gap since previous event from same agent",
    "EventIDThreatTier":    "threat tier classification of this Event ID (0=benign, 3=high-risk)",
    "EventIDRarity":        "how rare this Event ID is in the current batch",
    "MitreTacticWeight":    "MITRE ATT&CK tactic severity weight",
    "MitreTacticCount":     "number of MITRE tactics mapped to this event",
    "RuleLevel":            "Wazuh rule severity level (0-15)",
    "RuleLevelNorm":        "normalised Wazuh rule level",
    "CommandLineLength":    "length of the command line (longer = more suspicious)",
    "LogLength":            "raw log length",
    "LogEntropy":           "Shannon entropy of the log (high = obfuscated/encoded content)",
    "CommandLineEntropy":   "Shannon entropy of the command line",
    "ComputerEventCount":   "total number of events from this agent in the batch",
    "Hour":                 "hour of day (0-23)",
    "DayOfWeek":            "day of week (0=Monday, 6=Sunday)",
    "HourSin":              "cyclic hour encoding (sine)",
    "HourCos":              "cyclic hour encoding (cosine)",
    "MitrePresent":         "whether a MITRE ATT&CK ID was mapped to this event",
}


def _describe_feature(feature: str) -> str:
    """Return a human-readable description for a SHAP feature name."""
    return _FEATURE_DESCRIPTIONS.get(feature, feature.replace("_", " ").lower())


def _format_shap_contributions(shap_values: list[dict]) -> str:
    """Convert raw SHAP dicts into human-readable text for the LLM."""
    if not shap_values:
        return "  (no SHAP data available)"

    lines = []
    for sv in shap_values:
        feature   = sv.get("feature", "unknown")
        shap_val  = sv.get("shap_value", 0.0)
        alert_val = sv.get("alert_value", 0.0)
        direction = sv.get("direction", "unknown")

        direction_str = "↑ pushed toward ANOMALY" if shap_val > 0 else "↓ pushed toward NORMAL"
        desc = _describe_feature(feature)
        lines.append(
            f"  • [{feature}] = {alert_val} → {direction_str} "
            f"(SHAP impact: {shap_val:+.4f}) — {desc}"
        )
    return "\n".join(lines)


def _format_alert_for_prompt(alert: dict, is_anomaly: bool, index: int) -> str:
    """Render a single alert as a structured text block for the system prompt."""
    ts          = alert.get("timestamp", "unknown")
    agent       = alert.get("agent_name", "unknown")
    rule_desc   = alert.get("rule_description", "—")
    rule_level  = alert.get("rule_level", 0)
    event_id    = alert.get("event_id", "—")
    channel     = alert.get("channel", "—")
    target_user = alert.get("target_user", "")
    subject_user= alert.get("subject_user", "")
    cmd_line    = alert.get("command_line", "")
    src_ip      = alert.get("src_ip", "")
    full_log    = alert.get("full_log", "")
    rule_groups = ", ".join(alert.get("rule_groups", [])) or "—"
    mitre_ids   = ", ".join(alert.get("mitre_ids", [])) or "—"
    mitre_tacs  = ", ".join(alert.get("mitre_tactics", [])) or "—"
    mitre_techs = ", ".join(alert.get("mitre_techniques", [])) or "—"

    lines = [f"--- {'ANOMALY' if is_anomaly else 'NORMAL'} #{index} ---"]
    lines.append(f"Timestamp    : {ts}")
    lines.append(f"Agent        : {agent}")
    lines.append(f"Rule         : [{rule_level}] {rule_desc}")
    lines.append(f"Event ID     : {event_id}  |  Channel: {channel}")
    lines.append(f"Rule Groups  : {rule_groups}")
    lines.append(f"MITRE IDs    : {mitre_ids}")
    lines.append(f"MITRE Tactics: {mitre_tacs}")
    lines.append(f"MITRE Techs  : {mitre_techs}")

    if target_user:
        lines.append(f"Target User  : {target_user}")
    if subject_user:
        lines.append(f"Subject User : {subject_user}")
    if src_ip:
        lines.append(f"Source IP    : {src_ip}")
    if cmd_line:
        lines.append(f"Command Line : {cmd_line[:300]}{'…' if len(cmd_line) > 300 else ''}")

    if is_anomaly:
        score      = alert.get("anomaly_score", 0.0)
        confidence = alert.get("confidence", "—")
        cluster_id = alert.get("cluster_id", None)
        mitre_stage= alert.get("mitre_stage", "—")
        shap_vals  = alert.get("shap_values", [])

        lines.append(f"Anomaly Score: {score:.4f} ({(score*100):.1f}%) | Confidence: {confidence}")
        if cluster_id is not None:
            lines.append(f"Cluster ID   : {cluster_id}")
        lines.append(f"MITRE Stage  : {mitre_stage or '—'}")
        lines.append("SHAP Feature Contributions (why flagged):")
        lines.append(_format_shap_contributions(shap_vals))

    if full_log:
        truncated = full_log[:400]
        lines.append(f"Raw Log      : {truncated}{'…' if len(full_log) > 400 else ''}")

    return "\n".join(lines)


def build_system_prompt(pipeline_data: dict | None) -> str:
    """
    Build the full system prompt fed to Gemini.
    Includes: persona, pipeline metadata, anomaly details, normal baselines,
    and SHAP-based correlation hints.
    """

    base_persona = (
        "You are ATHEA, an expert AI security analyst embedded in the Wazuh-ATHEA dashboard. "
        "Your role is to help SOC analysts understand security anomalies detected by an ensemble "
        "ML model (Isolation Forest + Local Outlier Factor) with SHAP explainability.\n\n"
        "When answering:\n"
        "- Be specific and reference actual data from the alerts provided below.\n"
        "- Explain SHAP feature contributions in plain English (what the feature means, "
        "why a high/low value is suspicious).\n"
        "- Correlate anomalies with normal logs to highlight what makes the flagged events "
        "stand out from the baseline.\n"
        "- Map findings to MITRE ATT&CK tactics when available.\n"
        "- If no pipeline data is available yet, say so and ask the user to wait for the "
        "first analysis cycle to complete.\n"
        "- Format responses in clear markdown with headers, bullet points, and code blocks "
        "where appropriate.\n"
    )

    if not pipeline_data:
        return (
            base_persona
            + "\n\n[CONTEXT]: No pipeline data is available yet. "
            "The first analysis cycle may still be running. "
            "Inform the user and advise them to wait a moment before retrying."
        )

    # ── Pipeline metadata ───────────────────────────────────────────────────
    total_alerts   = pipeline_data.get("total_alerts", 0)
    anomaly_count  = pipeline_data.get("anomaly_count", 0)
    normal_count   = pipeline_data.get("normal_count", 0)
    model_used     = pipeline_data.get("model_used", "unknown")
    contamination  = pipeline_data.get("contamination_used", 0.0)
    minutes_back   = pipeline_data.get("minutes_back", 60)
    pipeline_ver   = pipeline_data.get("pipeline_version", "—")
    conf_dist      = pipeline_data.get("confidence_distribution", {})
    top_mitre      = pipeline_data.get("top_mitre_stages", [])

    conf_str = ", ".join(f"{k}: {v}" for k, v in conf_dist.items()) or "none"
    mitre_str = ", ".join(f"{stage} ({cnt})" for stage, cnt in top_mitre) or "none"

    meta_block = (
        f"=== PIPELINE METADATA ===\n"
        f"Pipeline Version : {pipeline_ver}\n"
        f"Analysis Window  : Last {minutes_back} minutes\n"
        f"ML Model         : {model_used}\n"
        f"Contamination    : {contamination:.1%} (sensitivity setting)\n"
        f"Total Alerts     : {total_alerts}\n"
        f"Anomalies Flagged: {anomaly_count}\n"
        f"Normal Alerts    : {normal_count}\n"
        f"Confidence Dist  : {conf_str}\n"
        f"Top MITRE Stages : {mitre_str}\n"
    )

    # ── Anomalies block ─────────────────────────────────────────────────────
    all_alerts = pipeline_data.get("alerts", [])
    anomalies  = [a for a in all_alerts if a.get("anomaly") == 1]
    normals    = [a for a in all_alerts if a.get("anomaly") != 1]

    # Sort anomalies by score descending, take top 20
    anomalies_sorted = sorted(
        anomalies,
        key=lambda a: a.get("anomaly_score", 0.0),
        reverse=True
    )[:20]

    anomaly_block_lines = [f"\n=== ANOMALOUS ALERTS ({len(anomalies)} total, showing top {len(anomalies_sorted)}) ==="]
    for i, alert in enumerate(anomalies_sorted, 1):
        anomaly_block_lines.append(_format_alert_for_prompt(alert, is_anomaly=True, index=i))

    # ── Normal baselines block ───────────────────────────────────────────────
    # Take a representative sample of normals — spread across agents
    agent_seen: set = set()
    normals_sample: list[dict] = []
    for alert in normals:
        agent = alert.get("agent_name", "unknown")
        if agent not in agent_seen or len(normals_sample) < 5:
            normals_sample.append(alert)
            agent_seen.add(agent)
        if len(normals_sample) >= 10:
            break

    normal_block_lines = [f"\n=== NORMAL (BASELINE) ALERTS ({normal_count} total, showing {len(normals_sample)} representative samples) ==="]
    normal_block_lines.append(
        "(These events were NOT flagged as anomalous — they represent typical/expected activity "
        "and serve as the baseline for comparison.)"
    )
    for i, alert in enumerate(normals_sample, 1):
        normal_block_lines.append(_format_alert_for_prompt(alert, is_anomaly=False, index=i))

    # ── Correlation hint ─────────────────────────────────────────────────────
    correlation_hint = (
        "\n=== CORRELATION GUIDANCE ===\n"
        "When explaining anomalies, compare them against the normal baseline above. "
        "For example:\n"
        "  - If a normal alert has RuleLevel 3 and the anomaly has RuleLevel 14, explain the difference.\n"
        "  - If SHAP shows IsFailedLogin=1 as the top contributor, compare the failed login ratio "
        "    in the anomaly vs the normal baseline.\n"
        "  - If LogEntropy is high in the anomaly but low in normals, suggest possible obfuscation.\n"
        "  - Reference cluster IDs to group related anomalies into attack campaigns.\n"
        "  - Use MITRE stages to narrate the attack kill chain if multiple stages appear.\n"
    )

    full_prompt = (
        base_persona
        + "\n\n"
        + meta_block
        + "\n".join(anomaly_block_lines)
        + "\n"
        + "\n".join(normal_block_lines)
        + "\n"
        + correlation_hint
        + "\n\n"
        + "Answer the analyst's question below using the data provided above. "
        "Be precise, cite specific alert details, and translate technical SHAP/ML "
        "jargon into actionable security insights.\n"
    )

    return full_prompt


def _convert_history_to_gemini(history: list[ChatMessage]) -> list[dict[str, Any]]:
    """Convert our ChatMessage list to the format Gemini expects."""
    gemini_history = []
    for msg in history:
        # Gemini uses "model" for assistant role
        role = "model" if msg.role in ("model", "assistant") else "user"
        gemini_history.append({
            "role": role,
            "parts": [{"text": msg.content}],
        })
    return gemini_history


# ── FastAPI Router ───────────────────────────────────────────────────────────
router = APIRouter(tags=["Chatbot"])


@router.post("/api/chat", response_model=ChatResponse)
async def chat(request: ChatRequest):
    """
    Send a message to the ATHEA Gemini chatbot.
    The chatbot is automatically provided the latest pipeline results as context.
    """
    # _state is injected via dependency — imported at call time from main.py
    from main import _state as app_state

    pipeline_data: dict | None = app_state.get("cached_results")

    if not _gemini_ready:
        raise HTTPException(
            status_code=503,
            detail="Gemini API key not configured. Please set GEMINI_API_KEY in your .env file.",
        )

    system_prompt = build_system_prompt(pipeline_data)
    context_loaded = pipeline_data is not None

    # Convert conversation history to Gemini format
    gemini_history = _convert_history_to_gemini(request.history)

    try:
        model = genai.GenerativeModel(
            model_name=GEMINI_MODEL,
            system_instruction=system_prompt,
        )

        chat_session = model.start_chat(history=gemini_history)
        response = chat_session.send_message(request.message)

        reply_text = response.text

    except Exception as exc:
        logger.error(f"Gemini API error: {exc}", exc_info=True)
        raise HTTPException(
            status_code=502,
            detail=f"Gemini API error: {str(exc)}",
        )

    return ChatResponse(
        reply=reply_text,
        model=GEMINI_MODEL,
        context_loaded=context_loaded,
    )
