

import logging
import os
from collections import Counter

from sklearn.cluster import HDBSCAN
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.neighbors import LocalOutlierFactor
from sklearn.preprocessing import StandardScaler

logger = logging.getLogger(__name__)

ML_MODEL = os.getenv("ML_MODEL", "ensemble").lower()
ML_CONTAMINATION = float(os.getenv("ML_CONTAMINATION", "0.0"))



_TACTIC_PRIORITY = [
    "impact", "exfiltration", "command-and-control", "lateral-movement",
    "collection", "credential-access", "defense-evasion", "privilege-escalation",
    "persistence", "execution", "initial-access", "discovery", "reconnaissance",
]

_FEATURE_TO_MITRE = {
    "IsLogCleared":    "Defense Evasion",
    "IsPrivilegeUse":  "Privilege Escalation",
    "IsFailedLogin":   "Credential Access",
    "IsScheduledTask": "Persistence",
    "IsServiceInstall":"Persistence",
    "IsLateralMove":   "Lateral Movement",
    "IsProcessCreation":"Execution",
    "IsNetworkConnection":"Command and Control",
    "IsRegistryMod":   "Defense Evasion",
    "IsPowerShell":    "Execution",
    "LogHasSuspicious": "Defense Evasion",
    "LogHasBase64":    "Defense Evasion",
}


def _infer_mitre_stage(alert: dict, feature_row: pd.Series | None) -> str | None:

    tactics = alert.get("mitre_tactics", [])
    if tactics:
        for t in _TACTIC_PRIORITY:
            for provided in tactics:
                if t in provided.lower():
                    return provided.replace("-", " ").title()
        return tactics[0].replace("-", " ").title()


    if feature_row is not None:
        for feat, stage in _FEATURE_TO_MITRE.items():
            if feat in feature_row.index and feature_row[feat] > 0.5:
                return stage

    return None




def _confidence_tier(score: float) -> str:
    if score >= 0.70:
        return "High"
    elif score >= 0.40:
        return "Medium"
    return "Low"




def _normalize(arr: np.ndarray) -> np.ndarray:
    lo, hi = arr.min(), arr.max()
    if hi == lo:
        return np.zeros_like(arr, dtype=float)
    return (arr - lo) / (hi - lo)




class AnomalyDetector:

    def __init__(self, model_type: str = ML_MODEL):
        self.model_type    = model_type
        self.scaler        = StandardScaler()
        self.if_model: IsolationForest | None     = None
        self.lof_model: LocalOutlierFactor | None = None
        self.X_scaled: np.ndarray | None          = None
        self.feature_columns: list[str]           = []



    @staticmethod
    def _contamination(n: int) -> float:
        if ML_CONTAMINATION > 0.0:
            return ML_CONTAMINATION
        if   n < 30:   return 0.30
        elif n < 80:   return 0.20
        elif n < 200:  return 0.15
        else:          return 0.10



    def fit_predict(self, feature_df: pd.DataFrame) -> dict:
        n = len(feature_df)
        self.feature_columns = list(feature_df.columns)


        if n < 5:
            logger.warning(f"Only {n} samples — skipping ML (need ≥ 5)")
            self.X_scaled = feature_df.values.astype(float)
            return {
                "anomaly_flags":     np.zeros(n, dtype=int),
                "scores_normalized": np.zeros(n),
                "contamination":     0.0,
            }

        c = self._contamination(n)
        logger.info(f"Running {self.model_type} on {n} samples (contamination={c:.0%})")


        X = self.scaler.fit_transform(feature_df.values)
        self.X_scaled = X


        n_est       = min(200, max(50, n // 4))
        max_samples = min(256, n)

        self.if_model = IsolationForest(
            n_estimators=n_est,
            max_samples=max_samples,
            contamination=c,
            bootstrap=True,
            random_state=42,
            n_jobs=-1,
        )
        if_pred   = self.if_model.fit_predict(X)
        if_score  = -self.if_model.decision_function(X)
        if_norm   = _normalize(if_score)


        if self.model_type in ("lof", "ensemble"):
            n_neighbors = max(5, min(20, n // 8))
            self.lof_model = LocalOutlierFactor(
                n_neighbors=n_neighbors,
                contamination=c,
                novelty=False,
                n_jobs=-1,
            )
            lof_pred  = self.lof_model.fit_predict(X)
            lof_score = -self.lof_model.negative_outlier_factor_
            lof_norm  = _normalize(lof_score)


        if self.model_type == "isolation_forest":
            scores_norm = if_norm
            flags = (if_pred == -1).astype(int)

        elif self.model_type == "lof":
            scores_norm = lof_norm
            flags = (lof_pred == -1).astype(int)

        else:
            scores_norm = 0.55 * if_norm + 0.45 * lof_norm
            threshold   = np.percentile(scores_norm, (1.0 - c) * 100)
            flags       = (scores_norm >= threshold).astype(int)

        n_anomalies = int(flags.sum())
        logger.info(f"Detected {n_anomalies} anomalies ({n_anomalies/n:.1%} of batch)")
        return {
            "anomaly_flags":     flags,
            "scores_normalized": scores_norm.astype(float),
            "contamination":     c,
        }




class AnomalyClusterer:
    MIN_CLUSTER_SAMPLES = 5

    def cluster(
        self,
        X_scaled: np.ndarray,
        anomaly_indices: np.ndarray,
        feature_columns: list[str],
    ) -> dict[int, int]:
        n_anom = len(anomaly_indices)
        if n_anom < self.MIN_CLUSTER_SAMPLES:
            logger.info(f"Too few anomalies ({n_anom}) for clustering — skipping.")
            return {int(i): -1 for i in anomaly_indices}

        X_anom = X_scaled[anomaly_indices]

        min_cluster = max(2, n_anom // 10)
        clusterer = HDBSCAN(
            min_cluster_size=min_cluster,
            min_samples=1,
            metric="euclidean",
            cluster_selection_method="eom",
        )
        labels = clusterer.fit_predict(X_anom)

        n_clusters = len(set(labels) - {-1})
        logger.info(f"HDBSCAN found {n_clusters} clusters in {n_anom} anomalies")

        return {int(anomaly_indices[i]): int(labels[i]) for i in range(n_anom)}




def detect_anomalies(
    feature_df: pd.DataFrame,
    alerts: list[dict],
    model_type: str = ML_MODEL,
) -> tuple[list[dict], AnomalyDetector, dict]:
    detector = AnomalyDetector(model_type=model_type)
    result   = detector.fit_predict(feature_df)

    anomaly_flags     = result["anomaly_flags"]
    scores_normalized = result["scores_normalized"]
    contamination     = result["contamination"]


    anomaly_indices = np.where(anomaly_flags == 1)[0]
    cluster_map: dict[int, int] = {}

    if detector.X_scaled is not None and len(anomaly_indices) > 0:
        clusterer   = AnomalyClusterer()
        cluster_map = clusterer.cluster(
            detector.X_scaled, anomaly_indices, detector.feature_columns
        )


    for i, alert in enumerate(alerts):
        is_anom     = int(anomaly_flags[i])
        score       = float(scores_normalized[i])
        feat_row    = feature_df.iloc[i] if i < len(feature_df) else None

        alert["anomaly"]       = is_anom
        alert["anomaly_score"] = round(score, 4)
        alert["confidence"]    = _confidence_tier(score) if is_anom else None
        alert["cluster_id"]    = cluster_map.get(i, None) if is_anom else None
        alert["mitre_stage"]   = _infer_mitre_stage(alert, feat_row) if is_anom else None
        alert["shap_values"]   = []


    n_anom = int(anomaly_flags.sum())
    confidence_dist = Counter(
        a["confidence"] for a in alerts if a.get("confidence")
    )
    mitre_dist = Counter(
        a["mitre_stage"] for a in alerts if a.get("mitre_stage")
    )

    meta = {
        "model_used":              model_type,
        "contamination_used":      round(contamination, 3),
        "anomaly_count":           n_anom,
        "normal_count":            len(alerts) - n_anom,
        "confidence_distribution": dict(confidence_dist),
        "top_mitre_stages":        mitre_dist.most_common(5),
    }

    return alerts, detector, meta
