"""
Sentinel AI - Isolation Forest Model Implementation (Phase 2)
Encapsulates Scikit-learn's IsolationForest for unsupervised security telemetry anomaly detection.
Uses the 9 canonical features prepared in Phase 1 with reproducible random seed and input validation.

Note: In Phase 2, this module provides model training and scoring independently.
It does NOT create database alerts and does NOT integrate into the live alert pipeline.
"""
from dataclasses import dataclass
from datetime import datetime, timezone
import math
from typing import Any, Dict, List, Optional, Sequence, Union
import numpy as np
from sklearn.ensemble import IsolationForest

from backend.app.ml.config import (
    ML_FEATURE_NAMES,
    IsolationForestConfig,
    ml_config
)
from backend.app.ml.preprocessing import (
    preprocess_feature_batch,
    preprocess_feature_dict,
    validate_feature_matrix
)


def _compute_normalized_anomaly_score(raw_score: float) -> float:
    """
    Maps Scikit-learn's decision_function score to a normalized [0.0, 1.0] anomaly score.
    In IsolationForest:
      - raw_score > 0 indicates normal/inlier.
      - raw_score < 0 indicates outlier/anomaly.
      - raw_score == 0 is the decision threshold.

    Uses a continuous logistic sigmoid mapping:
      anomaly_score = 1 / (1 + exp(5.0 * raw_score))
      - raw_score = +0.20 -> anomaly_score ~= 0.27 (benign)
      - raw_score = 0.00  -> anomaly_score = 0.50 (threshold boundary)
      - raw_score = -0.20 -> anomaly_score ~= 0.73 (anomalous)
    """
    try:
        # Scale factor 5.0 provides smooth separation across [-0.5, 0.5] range
        normalized = 1.0 / (1.0 + math.exp(min(50.0, max(-50.0, 5.0 * raw_score))))
        return round(float(normalized), 4)
    except (OverflowError, ValueError):
        return 1.0 if raw_score < 0 else 0.0


class IsolationForestModel:
    """
    Modular wrapper around Scikit-learn's IsolationForest estimator.
    Enforces strict feature dimensionality, reproducible training, and
    provides a unified prediction interface.
    """

    SCORE_INTERPRETATION = (
        "raw_score represents Scikit-learn decision_function output: values >= 0.0 indicate "
        "normal baseline traffic, values < 0.0 indicate statistical anomalies. "
        "anomaly_score is normalized from 0.0 (most benign) to 1.0 (most anomalous). "
        "Note: A statistical anomaly indicates an unusual behavioral deviation and is "
        "not necessarily malicious."
    )

    def __init__(self, config: Optional[IsolationForestConfig] = None):
        self.config = config if config is not None else ml_config.isolation_forest
        self.feature_names = list(ML_FEATURE_NAMES)
        self.is_fitted: bool = False
        self.sample_count: int = 0
        self.trained_at: Optional[str] = None
        self.threshold: float = float(self.config.anomaly_threshold)

        # Underlying scikit-learn estimator
        self._clf = IsolationForest(
            n_estimators=self.config.n_estimators,
            contamination=self.config.contamination,
            max_samples=self.config.max_samples,
            max_features=self.config.max_features,
            bootstrap=self.config.bootstrap,
            random_state=self.config.random_state,
            n_jobs=self.config.n_jobs
        )

    def fit(self, X: np.ndarray) -> "IsolationForestModel":
        """
        Trains the Isolation Forest model on a 2D numerical feature matrix.
        Validates dimensions and feature ordering before fitting.
        """
        validate_feature_matrix(X, expected_features=len(self.feature_names))

        self._clf.fit(X)
        self.is_fitted = True
        self.sample_count = int(X.shape[0])
        self.trained_at = datetime.now(timezone.utc).isoformat()
        return self

    def _ensure_fitted(self) -> None:
        if not self.is_fitted:
            raise RuntimeError(
                "IsolationForestModel is not fitted. Train the model using .fit() "
                "or load a trained model via model_store.load_model() before predicting."
            )

    def decision_function(self, X: np.ndarray) -> np.ndarray:
        """Computes raw decision scores for a feature matrix. Negative values indicate anomalies."""
        self._ensure_fitted()
        validate_feature_matrix(X, expected_features=len(self.feature_names))
        return self._clf.decision_function(X)

    def predict_raw(self, X: np.ndarray) -> np.ndarray:
        """Returns raw Scikit-learn predictions (+1 for normal, -1 for anomaly)."""
        self._ensure_fitted()
        validate_feature_matrix(X, expected_features=len(self.feature_names))
        return self._clf.predict(X)

    def predict(
        self,
        data: Union[np.ndarray, Dict[str, Any], Sequence[Dict[str, Any]]],
        threshold: Optional[float] = None
    ) -> List[Dict[str, Any]]:
        """
        Unified prediction interface accepting:
        - 2D NumPy array of shape (n_samples, 9)
        - Single feature dictionary
        - Sequence of feature dictionaries

        Args:
            data: Input feature vector(s) or dictionary.
            threshold: Optional custom decision threshold on raw_score.
                       If None, uses self.threshold (default 0.0).

        Returns a list of structured prediction results:
        [
            {
                "prediction": "NORMAL" | "ANOMALY",
                "is_anomaly": False | True,
                "raw_score": float,
                "anomaly_score": float,
                "interpretation": str
            },
            ...
        ]
        """
        self._ensure_fitted()

        # Input preprocessing & validation
        if isinstance(data, dict):
            X = preprocess_feature_dict(data, feature_names=self.feature_names)
        elif isinstance(data, np.ndarray):
            X = data
            validate_feature_matrix(X, expected_features=len(self.feature_names))
        elif isinstance(data, (list, tuple)):
            X = preprocess_feature_batch(data, feature_names=self.feature_names)
        else:
            raise TypeError(f"Unsupported data type for prediction: {type(data).__name__}")

        if X.shape[0] == 0:
            return []

        eff_threshold = threshold if threshold is not None else self.threshold
        raw_scores = self._clf.decision_function(X)

        results: List[Dict[str, Any]] = []
        for i in range(len(raw_scores)):
            raw_sc = float(raw_scores[i])
            is_anomaly = bool(raw_sc < eff_threshold)
            normalized_sc = _compute_normalized_anomaly_score(raw_sc)

            results.append({
                "prediction": "ANOMALY" if is_anomaly else "NORMAL",
                "is_anomaly": is_anomaly,
                "raw_score": round(raw_sc, 6),
                "anomaly_score": normalized_sc,
                "interpretation": self.SCORE_INTERPRETATION
            })

        return results

    def predict_single(
        self,
        sample: Union[Dict[str, Any], np.ndarray],
        threshold: Optional[float] = None
    ) -> Dict[str, Any]:
        """Convenience method for predicting on a single sample."""
        results = self.predict(sample, threshold=threshold)
        if not results:
            raise ValueError("No prediction results generated for sample.")
        return results[0]

    def get_metadata(self) -> Dict[str, Any]:
        """Returns serializable model metadata."""
        return {
            "model_type": "IsolationForest",
            "model_version": ml_config.model_version,
            "feature_names": list(self.feature_names),
            "feature_count": len(self.feature_names),
            "is_fitted": self.is_fitted,
            "sample_count": self.sample_count,
            "trained_at": self.trained_at,
            "threshold": self.threshold,
            "hyperparameters": {
                "n_estimators": self.config.n_estimators,
                "contamination": self.config.contamination,
                "max_samples": self.config.max_samples,
                "max_features": self.config.max_features,
                "bootstrap": self.config.bootstrap,
                "random_state": self.config.random_state,
                "n_jobs": self.config.n_jobs,
                "anomaly_threshold": self.config.anomaly_threshold
            }
        }

