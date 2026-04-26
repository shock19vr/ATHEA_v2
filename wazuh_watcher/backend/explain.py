import logging
import os

import numpy as np
import pandas as pd
import shap

logger = logging.getLogger(__name__)

SHAP_TOP_N       = int(os.getenv("SHAP_TOP_N", "6"))
MAX_EXPLAIN_ROWS = int(os.getenv("MAX_EXPLAIN_ROWS", "150"))


class SHAPExplainer:

    def __init__(self, feature_columns: list[str]):
        self.feature_columns = feature_columns

    def explain_anomalies(
        self,
        if_model,           # Fitted IsolationForest instance
        X_scaled: np.ndarray,
        feature_df: pd.DataFrame,
        anomaly_indices: np.ndarray,
        top_n: int = SHAP_TOP_N,
    ) -> dict[int, list[dict]]:
        if if_model is None:
            logger.warning("No IF model available for SHAP — skipping.")
            return {}

        if len(anomaly_indices) == 0:
            return {}


        indices_to_explain = anomaly_indices[:MAX_EXPLAIN_ROWS]
        if len(anomaly_indices) > MAX_EXPLAIN_ROWS:
            logger.warning(
                f"Capping SHAP explanations at {MAX_EXPLAIN_ROWS} "
                f"(had {len(anomaly_indices)} anomalies)"
            )

        X_subset = X_scaled[indices_to_explain]


        try:
            explainer = shap.TreeExplainer(if_model)
        except Exception as e:
            logger.error(f"TreeExplainer init failed: {e}")
            return {}


        try:
            shap_matrix = explainer.shap_values(
                X_subset, check_additivity=False
            )
            if isinstance(shap_matrix, list):
                shap_matrix = shap_matrix[0]
        except Exception as e:
            logger.error(f"SHAP computation failed: {e}")
            return {}


        results: dict[int, list[dict]] = {}

        for local_i, global_i in enumerate(indices_to_explain):
            row_shap = shap_matrix[local_i]
            row_feat = (
                feature_df.iloc[global_i]
                if global_i < len(feature_df)
                else None
            )


            sorted_fi = np.argsort(np.abs(row_shap))[::-1][:top_n]

            contributions = []
            for fi in sorted_fi:
                feat_name   = self.feature_columns[fi] if fi < len(self.feature_columns) else f"f{fi}"
                shap_val    = float(row_shap[fi])
                alert_val   = float(row_feat[feat_name]) if (row_feat is not None and feat_name in row_feat.index) else 0.0

                contributions.append({
                    "feature":    feat_name,
                    "shap_value": round(shap_val, 4),
                    "alert_value": round(alert_val, 4),
                    "abs_impact":  round(abs(shap_val), 4),
                    "direction":  "anomalous" if shap_val > 0 else "normal",
                })

            results[int(global_i)] = contributions

        logger.info(f"SHAP computed for {len(results)} anomalies ({top_n} features each)")
        return results


def attach_shap_to_alerts(
    alerts: list[dict],
    shap_map: dict[int, list[dict]],
) -> list[dict]:
    for i, alert in enumerate(alerts):
        alert["shap_values"] = shap_map.get(i, [])
    return alerts
