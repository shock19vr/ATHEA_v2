

import logging
import os
import numpy as np

from wazuh_client import fetch_alerts
from features import WazuhFeatureEngineer
from model import detect_anomalies
from explain import SHAPExplainer, attach_shap_to_alerts

logger = logging.getLogger(__name__)

ML_MODEL    = os.getenv("ML_MODEL", "ensemble").lower()
SHAP_TOP_N  = int(os.getenv("SHAP_TOP_N", "6"))

_feature_engineer = WazuhFeatureEngineer()


async def run_pipeline(minutes_back: int = 60) -> dict:


    logger.info(f"Pipeline: fetching last {minutes_back}m of alerts…")
    alerts = await fetch_alerts(minutes_back=minutes_back)

    if not alerts:
        return _empty_response(minutes_back)


    logger.info(f"Pipeline: extracting features from {len(alerts)} alerts…")
    try:
        feature_df = _feature_engineer.extract_features(alerts)
    except Exception as exc:
        logger.error(f"Feature extraction failed: {exc}", exc_info=True)
        raise RuntimeError(f"Feature extraction error: {exc}") from exc

    logger.info(f"Pipeline: feature matrix {feature_df.shape[0]}×{feature_df.shape[1]}")


    logger.info(f"Pipeline: running {ML_MODEL} anomaly detection…")
    try:
        alerts, detector, meta = detect_anomalies(
            feature_df=feature_df,
            alerts=alerts,
            model_type=ML_MODEL,
        )
    except Exception as exc:
        logger.error(f"ML detection failed: {exc}", exc_info=True)
        raise RuntimeError(f"ML error: {exc}") from exc

    logger.info(
        f"Pipeline: {meta['anomaly_count']} anomalies detected "
        f"({meta['confidence_distribution']})"
    )


    anomaly_indices = np.where(
        np.array([a.get("anomaly", 0) for a in alerts]) == 1
    )[0]

    shap_map: dict = {}
    if detector.if_model is not None and len(anomaly_indices) > 0:
        logger.info(f"Pipeline: computing SHAP for {len(anomaly_indices)} anomalies…")
        try:
            explainer = SHAPExplainer(feature_columns=detector.feature_columns)
            shap_map  = explainer.explain_anomalies(
                if_model        = detector.if_model,
                X_scaled        = detector.X_scaled,
                feature_df      = feature_df,
                anomaly_indices = anomaly_indices,
                top_n           = SHAP_TOP_N,
            )
            alerts = attach_shap_to_alerts(alerts, shap_map)
        except Exception as exc:
            logger.warning(f"SHAP failed (non-fatal): {exc}", exc_info=True)
    else:
        if len(anomaly_indices) == 0:
            logger.info("Pipeline: no anomalies — SHAP skipped.")
        else:
            logger.warning("Pipeline: IF model not available — SHAP skipped.")


    return {
        "pipeline_version":        "3.0-ml-shap",
        "minutes_back":            minutes_back,
        "total_alerts":            len(alerts),
        "anomaly_count":           meta["anomaly_count"],
        "normal_count":            meta["normal_count"],
        "model_used":              meta["model_used"],
        "contamination_used":      meta["contamination_used"],
        "confidence_distribution": meta["confidence_distribution"],
        "top_mitre_stages":        meta["top_mitre_stages"],
        "feature_columns":         detector.feature_columns,
        "alerts":                  alerts,
    }


def _empty_response(minutes_back: int) -> dict:
    return {
        "pipeline_version":        "3.0-ml-shap",
        "minutes_back":            minutes_back,
        "total_alerts":            0,
        "anomaly_count":           0,
        "normal_count":            0,
        "model_used":              ML_MODEL,
        "contamination_used":      0.0,
        "confidence_distribution": {},
        "top_mitre_stages":        [],
        "feature_columns":         _feature_engineer.FEATURE_COLUMNS,
        "alerts":                  [],
    }

