"""
Sentinel AI - ML Model Evaluation & Threshold Tuning (Phase 3)
Provides a rigorous, reproducible evaluation framework for Isolation Forest anomaly detection.
Computes standard classification metrics, tunes decision thresholds via validation splits,
and evaluates scenario-wise detection sensitivity without Pandas.
"""
from dataclasses import dataclass, asdict
from typing import Any, Dict, List, Optional, Sequence, Tuple, Union
import numpy as np

from backend.app.ml.config import ML_FEATURE_NAMES, ml_config
from backend.app.ml.model import IsolationForestModel
from backend.app.ml.preprocessing import validate_feature_matrix
from backend.app.ml.training_data import generate_evaluation_splits


@dataclass
class EvaluationMetrics:
    """Standard binary classification and anomaly detection metrics container."""
    tp: int
    tn: int
    fp: int
    fn: int
    total: int
    accuracy: float
    precision: float
    recall: float        # Equivalent to TPR / Detection Rate
    tpr: float           # True Positive Rate
    fpr: float           # False Positive Rate
    f1_score: float

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def calculate_metrics(y_true: np.ndarray, y_pred: np.ndarray) -> EvaluationMetrics:
    """
    Computes comprehensive evaluation metrics comparing ground truth (y_true)
    and binary model predictions (y_pred):
    - 0 represents Normal
    - 1 represents Anomaly

    Handles all division-by-zero cases safely (returns 0.0).
    """
    y_true_arr = np.asarray(y_true, dtype=int).ravel()
    y_pred_arr = np.asarray(y_pred, dtype=int).ravel()

    if len(y_true_arr) != len(y_pred_arr):
        raise ValueError(
            f"Shape mismatch: y_true has {len(y_true_arr)} items, y_pred has {len(y_pred_arr)} items."
        )

    total = len(y_true_arr)
    if total == 0:
        return EvaluationMetrics(
            tp=0, tn=0, fp=0, fn=0, total=0,
            accuracy=0.0, precision=0.0, recall=0.0, tpr=0.0, fpr=0.0, f1_score=0.0
        )

    tp = int(np.sum((y_true_arr == 1) & (y_pred_arr == 1)))
    tn = int(np.sum((y_true_arr == 0) & (y_pred_arr == 0)))
    fp = int(np.sum((y_true_arr == 0) & (y_pred_arr == 1)))
    fn = int(np.sum((y_true_arr == 1) & (y_pred_arr == 0)))

    accuracy = round((tp + tn) / total, 4)

    # Precision = TP / (TP + FP)
    precision = round(tp / (tp + fp), 4) if (tp + fp) > 0 else 0.0

    # Recall (TPR / Detection Rate) = TP / (TP + FN)
    recall = round(tp / (tp + fn), 4) if (tp + fn) > 0 else 0.0
    tpr = recall

    # False Positive Rate = FP / (FP + TN)
    fpr = round(fp / (fp + tn), 4) if (fp + tn) > 0 else 0.0

    # F1 Score = 2 * (Precision * Recall) / (Precision + Recall)
    if precision + recall > 0:
        f1_score = round(2.0 * (precision * recall) / (precision + recall), 4)
    else:
        f1_score = 0.0

    return EvaluationMetrics(
        tp=tp,
        tn=tn,
        fp=fp,
        fn=fn,
        total=total,
        accuracy=accuracy,
        precision=precision,
        recall=recall,
        tpr=tpr,
        fpr=fpr,
        f1_score=f1_score
    )


def evaluate_dataset(
    model: IsolationForestModel,
    X: np.ndarray,
    y: np.ndarray,
    threshold: Optional[float] = None
) -> Dict[str, Any]:
    """
    Evaluates a trained IsolationForestModel against a labeled feature matrix.

    Args:
        model: Trained IsolationForestModel instance.
        X: (N, 9) feature matrix.
        y: (N,) binary ground truth array (0=Normal, 1=Anomaly).
        threshold: Decision threshold on raw decision_function score (< threshold indicates anomaly).

    Returns:
        Dictionary containing computed metrics and raw score distribution summaries.
    """
    if not model.is_fitted:
        raise RuntimeError("Cannot evaluate an unfitted model.")

    validate_feature_matrix(X, expected_features=len(ML_FEATURE_NAMES))
    raw_scores = model.decision_function(X)

    eff_threshold = threshold if threshold is not None else model.threshold
    y_pred = (raw_scores < eff_threshold).astype(int)

    metrics = calculate_metrics(y, y_pred)

    return {
        "metrics": metrics.to_dict(),
        "threshold_applied": eff_threshold,
        "raw_scores": {
            "mean": round(float(np.mean(raw_scores)), 4),
            "min": round(float(np.min(raw_scores)), 4),
            "max": round(float(np.max(raw_scores)), 4),
            "std": round(float(np.std(raw_scores)), 4)
        }
    }


def evaluate_scenarios(
    model: IsolationForestModel,
    X: np.ndarray,
    y: np.ndarray,
    scenarios: List[str],
    threshold: Optional[float] = None
) -> Dict[str, Any]:
    """
    Computes scenario-wise detection breakdowns for individual attack types and normal traffic:
    - normal
    - brute_force
    - port_scan
    - ddos
    - data_burst

    Reports detection rates, false positive rates, and flags any scenarios where the model struggles.
    """
    if len(X) != len(scenarios) or len(X) != len(y):
        raise ValueError("X, y, and scenarios must have identical lengths.")

    eff_threshold = threshold if threshold is not None else model.threshold
    raw_scores = model.decision_function(X)
    y_pred = (raw_scores < eff_threshold).astype(int)

    unique_scenarios = sorted(list(set(scenarios)))
    scenario_results: Dict[str, Any] = {}
    struggling_scenarios: List[str] = []

    for sc in unique_scenarios:
        indices = [i for i, s in enumerate(scenarios) if s == sc]
        sc_y_true = y[indices]
        sc_y_pred = y_pred[indices]
        sc_scores = raw_scores[indices]
        sc_count = len(indices)

        predicted_anomalies = int(np.sum(sc_y_pred == 1))
        predicted_normal = int(np.sum(sc_y_pred == 0))

        # Distinguish normal traffic (baseline or borderline normal) from attack anomalies
        is_normal_type = bool(np.all(sc_y_true == 0))

        if is_normal_type:
            # For normal traffic: Detection Rate is True Negative Rate (Specificity)
            tnr = round(predicted_normal / sc_count, 4) if sc_count > 0 else 0.0
            fpr = round(predicted_anomalies / sc_count, 4) if sc_count > 0 else 0.0
            scenario_results[sc] = {
                "sample_count": sc_count,
                "predicted_normal": predicted_normal,
                "false_positives": predicted_anomalies,
                "specificity": tnr,
                "fpr": fpr,
                "mean_raw_score": round(float(np.mean(sc_scores)), 4),
                "status": "PASS" if fpr <= 0.15 else "ELEVATED_FPR"
            }
        else:
            # For anomaly attacks: Detection Rate is True Positive Rate (Recall)
            detection_rate = round(predicted_anomalies / sc_count, 4) if sc_count > 0 else 0.0
            status = "STRONG" if detection_rate >= 0.90 else ("MODERATE" if detection_rate >= 0.70 else "STRUGGLING")
            if detection_rate < 0.85:
                struggling_scenarios.append(sc)

            scenario_results[sc] = {
                "sample_count": sc_count,
                "true_positives": predicted_anomalies,
                "false_negatives": predicted_normal,
                "detection_rate": detection_rate,
                "mean_raw_score": round(float(np.mean(sc_scores)), 4),
                "status": status
            }

    overall_metrics = calculate_metrics(y, y_pred)

    return {
        "threshold_applied": eff_threshold,
        "overall_metrics": overall_metrics.to_dict(),
        "scenarios": scenario_results,
        "struggling_scenarios": struggling_scenarios
    }


def tune_threshold(
    model: IsolationForestModel,
    X_val: np.ndarray,
    y_val: np.ndarray,
    candidate_thresholds: Optional[Sequence[float]] = None,
    max_fpr: float = 0.10
) -> Tuple[float, List[Dict[str, Any]], Dict[str, Any]]:
    """
    Evaluates multiple candidate decision thresholds strictly on the VALIDATION dataset.
    Never evaluates on the held-out test dataset during tuning.

    Selection strategy:
    1. Evaluates candidates across F1-score, Precision, Recall, and FPR.
    2. Filters candidates that maintain an acceptable False Positive Rate (FPR <= max_fpr).
    3. Selects the candidate that maximizes F1-score within the FPR constraint.
    4. If tied, chooses the candidate closest to the standard baseline (0.0).

    Returns:
        best_threshold: Selected optimal raw score threshold.
        threshold_grid: Detailed metrics for all evaluated thresholds.
        best_metrics: Metrics dictionary for the selected threshold.
    """
    if candidate_thresholds is None:
        # Standard candidate grid centered around the default 0.0
        candidate_thresholds = [-0.15, -0.10, -0.05, -0.02, 0.0, 0.02, 0.05, 0.10]

    raw_scores = model.decision_function(X_val)
    threshold_grid: List[Dict[str, Any]] = []

    best_threshold = 0.0
    best_f1 = -1.0
    best_metrics: Dict[str, Any] = {}

    for t in sorted(candidate_thresholds):
        y_pred = (raw_scores < t).astype(int)
        metrics = calculate_metrics(y_val, y_pred)
        entry = {
            "threshold": round(float(t), 4),
            "tp": metrics.tp,
            "tn": metrics.tn,
            "fp": metrics.fp,
            "fn": metrics.fn,
            "accuracy": metrics.accuracy,
            "precision": metrics.precision,
            "recall": metrics.recall,
            "f1_score": metrics.f1_score,
            "fpr": metrics.fpr
        }
        threshold_grid.append(entry)

        # Selection criteria: respect FPR bound, maximize F1
        if metrics.fpr <= max_fpr:
            if metrics.f1_score > best_f1:
                best_f1 = metrics.f1_score
                best_threshold = float(t)
                best_metrics = entry
            elif metrics.f1_score == best_f1 and abs(t) < abs(best_threshold):
                best_threshold = float(t)
                best_metrics = entry

    # Fallback if no threshold met the FPR constraint
    if not best_metrics:
        # Pick threshold with lowest FPR
        best_entry = min(threshold_grid, key=lambda x: x["fpr"])
        best_threshold = best_entry["threshold"]
        best_metrics = best_entry

    return best_threshold, threshold_grid, best_metrics


def run_comprehensive_evaluation(
    model: Optional[IsolationForestModel] = None,
    splits: Optional[Dict[str, Any]] = None,
    candidate_thresholds: Optional[Sequence[float]] = None
) -> Dict[str, Any]:
    """
    Executes the full Phase 3 evaluation pipeline:
    1. Generates or uses segregated Train, Validation, and Test datasets.
    2. Trains model on Train set (if unprovided).
    3. Tunes threshold strictly on Validation set.
    4. Evaluates held-out Test set using baseline (0.0) AND tuned threshold.
    5. Computes scenario-wise detection performance on held-out Test set.
    6. Identifies any scenarios where the model struggles.
    """
    if splits is None:
        splits = generate_evaluation_splits(
            n_train_normal=250,
            n_val_normal=100,
            n_val_per_anomaly=25,
            n_test_normal=100,
            n_test_per_anomaly=25,
            base_seed=42
        )

    # 1. Ensure trained model
    if model is None:
        model = IsolationForestModel()
        model.fit(splits["train"]["X"])

    # 2. Tune threshold strictly on Validation set (held out from training)
    val_X = splits["validation"]["X"]
    val_y = splits["validation"]["y"]
    best_threshold, threshold_grid, val_metrics = tune_threshold(
        model=model,
        X_val=val_X,
        y_val=val_y,
        candidate_thresholds=candidate_thresholds
    )

    # 3. Evaluate held-out Test set with Baseline Threshold (0.0)
    test_X = splits["test"]["X"]
    test_y = splits["test"]["y"]
    test_scenarios = splits["test"]["scenarios"]

    baseline_test_eval = evaluate_scenarios(
        model=model,
        X=test_X,
        y=test_y,
        scenarios=test_scenarios,
        threshold=0.0
    )

    # 4. Evaluate held-out Test set with Tuned Threshold
    tuned_test_eval = evaluate_scenarios(
        model=model,
        X=test_X,
        y=test_y,
        scenarios=test_scenarios,
        threshold=best_threshold
    )

    # 5. Evaluate held-out Challenging Test set (Subtle attacks & Borderline normal)
    challenging_test_eval = None
    challenging_struggling: List[str] = []
    if "challenging_test" in splits:
        c_test_X = splits["challenging_test"]["X"]
        c_test_y = splits["challenging_test"]["y"]
        c_test_scenarios = splits["challenging_test"]["scenarios"]

        challenging_test_eval = evaluate_scenarios(
            model=model,
            X=c_test_X,
            y=c_test_y,
            scenarios=c_test_scenarios,
            threshold=best_threshold
        )
        challenging_struggling = challenging_test_eval["struggling_scenarios"]

    dataset_sizes: Dict[str, Any] = {
        "train_samples": len(splits["train"]["X"]),
        "validation_samples": len(val_X),
        "test_samples": len(test_X),
        "validation_normal": int(np.sum(val_y == 0)),
        "validation_anomalies": int(np.sum(val_y == 1)),
        "test_normal": int(np.sum(test_y == 0)),
        "test_anomalies": int(np.sum(test_y == 1))
    }
    if "challenging_test" in splits:
        dataset_sizes["challenging_test_samples"] = len(splits["challenging_test"]["X"])
        dataset_sizes["challenging_test_normal"] = int(np.sum(splits["challenging_test"]["y"] == 0))
        dataset_sizes["challenging_test_anomalies"] = int(np.sum(splits["challenging_test"]["y"] == 1))

    return {
        "dataset_sizes": dataset_sizes,
        "threshold_tuning": {
            "selected_threshold": best_threshold,
            "baseline_threshold": 0.0,
            "validation_metrics": val_metrics,
            "candidate_grid": threshold_grid
        },
        "held_out_test_baseline": baseline_test_eval,
        "held_out_test_tuned": tuned_test_eval,
        "struggling_scenarios": tuned_test_eval["struggling_scenarios"],
        "held_out_challenging_test": challenging_test_eval,
        "challenging_struggling_scenarios": challenging_struggling
    }

