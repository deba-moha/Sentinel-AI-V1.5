"""
Sentinel AI - ML Model Evaluation CLI Entrypoint (Phase 3)
Executes reproducible evaluation across Training, Validation, and Held-out Test datasets.
Prints formatted metric tables, threshold tuning curves, and scenario-wise sensitivity breakdowns.

Note: Standalone evaluation script. Never runs automatically at server startup.
Never overwrites existing saved models during evaluation.
"""
from pathlib import Path
from typing import Any, Dict, Optional
import numpy as np

from backend.app.ml.config import DEFAULT_MODEL_PATH, ml_config
from backend.app.ml.evaluation import run_comprehensive_evaluation
from backend.app.ml.model_store import load_model, model_exists


def run_evaluation_cli(
    model_path: Optional[str] = None,
    train_if_missing: bool = False,
    verbose: bool = True
) -> Dict[str, Any]:
    """
    Executes the comprehensive evaluation pipeline with safe model-loading semantics.

    Correction 1 Rules:
    - Never silently swallow deserialization, schema, or corruption errors.
    - If a saved model exists but cannot be loaded, stop evaluation and raise an error.
    - If no saved model exists, do not silently train unless train_if_missing=True.
    - Explicitly state whether evaluation used a saved model or a temporary in-memory model.
    - Never overwrite any model artifact on disk during evaluation.
    """
    target_path = Path(model_path) if model_path is not None else Path(ml_config.model_path)
    model = None
    model_source = "unknown"
    model_source_desc = ""

    if model_exists(target_path):
        try:
            model = load_model(target_path)
            model_source = "saved_model"
            model_source_desc = f"Saved model artifact loaded from '{target_path}'"
            if verbose:
                print(f"[*] Successfully loaded trained model from: {target_path}")
        except Exception as exc:
            if verbose:
                print(f"\n[FATAL ERROR] Failed to load saved model from '{target_path}':")
                print(f"              {type(exc).__name__}: {exc}")
                print("[FATAL ERROR] Evaluation aborted due to model corruption or schema incompatibility.\n")
            raise RuntimeError(
                f"Failed to load saved model from '{target_path}' ({type(exc).__name__}: {exc}). "
                f"Evaluation aborted to prevent silent fallback or corrupted evaluation."
            ) from exc
    else:
        if not train_if_missing:
            msg = (
                f"No saved model found at '{target_path}'.\n"
                f"Evaluation aborted because no persisted model is available.\n"
                f"To train and save a model first, execute: python -m backend.app.ml.train\n"
                f"To evaluate a temporary in-memory model without saving, run with '--train-if-missing' "
                f"or pass train_if_missing=True."
            )
            if verbose:
                print(f"\n[!] {msg}\n")
            raise FileNotFoundError(msg)
        else:
            model = None
            model_source = "temporary_in_memory"
            model_source_desc = "Temporary in-memory model (trained on clean training split; NOT saved to disk)"
            if verbose:
                print(f"[*] No saved model found at '{target_path}'.")
                print("[*] Option '--train-if-missing' is ACTIVE: training temporary in-memory model on baseline data.")
                print("[*] Note: The temporary model will NOT be saved to disk.")

    report = run_comprehensive_evaluation(model=model)
    report["model_info"] = {
        "source": model_source,
        "description": model_source_desc,
        "path": str(target_path),
        "persisted": (model_source == "saved_model")
    }

    if verbose:
        ds = report["dataset_sizes"]
        tt = report["threshold_tuning"]
        test_base = report["held_out_test_baseline"]
        test_tuned = report["held_out_test_tuned"]
        scenarios = test_tuned["scenarios"]
        challenging_test = report.get("held_out_challenging_test")

        print("\n" + "=" * 76)
        print("          SENTINEL AI V1.5 - ISOLATION FOREST EVALUATION REPORT        ")
        print("=" * 76)
        print(f" * Model Source:        {model_source.upper()}")
        print(f" * Model Details:       {model_source_desc}")
        print(f" * Target Model Path:   {target_path}")
        print(f" * Persisted on Disk:   {report['model_info']['persisted']}")

        print("\n[1] DATASET SPLITS (ZERO DATA LEAKAGE)")
        print("-" * 76)
        print(f" * Training Baseline (Normal only):      {ds['train_samples']} samples")
        print(f" * Canonical Validation Set (Tuning):    {ds['validation_samples']} samples ({ds['validation_normal']} Normal, {ds['validation_anomalies']} Anomalous)")
        print(f" * Canonical Held-Out Test Set (Eval):   {ds['test_samples']} samples ({ds['test_normal']} Normal, {ds['test_anomalies']} Anomalous)")
        if challenging_test is not None:
            c_samples = ds.get("challenging_test_samples", 0)
            c_norm = ds.get("challenging_test_normal", 0)
            c_anom = ds.get("challenging_test_anomalies", 0)
            print(f" * Challenging Held-Out Test Set (Eval): {c_samples} samples ({c_norm} Borderline Normal, {c_anom} Subtle Anomalies)")

        print("\n[2] VALIDATION THRESHOLD TUNING (HELD-OUT FROM TEST)")
        print("-" * 76)
        print(f"{'Threshold':>10} | {'Precision':>9} | {'Recall (TPR)':>12} | {'F1-Score':>9} | {'FPR':>7}")
        print("-" * 55)
        for cand in tt["candidate_grid"]:
            marker = " <-- SELECTED" if cand["threshold"] == tt["selected_threshold"] else ""
            print(f"{cand['threshold']:>10.4f} | {cand['precision']:>9.4f} | {cand['recall']:>12.4f} | {cand['f1_score']:>9.4f} | {cand['fpr']:>7.4f}{marker}")

        print(f"\n * Selected Threshold: {tt['selected_threshold']:.4f} (Baseline: {tt['baseline_threshold']:.4f})")
        print(f" * Trade-Off Rationale: Maximizes F1-score while maintaining FPR <= 10%.")

        print("\n[3] CANONICAL BENCHMARK: HELD-OUT TEST PERFORMANCE")
        print("-" * 76)
        b_met = test_base["overall_metrics"]
        t_met = test_tuned["overall_metrics"]
        print(f"{'Metric':<25} | {'Baseline (0.0)':>15} | {'Tuned (' + str(tt['selected_threshold']) + ')':>15}")
        print("-" * 60)
        print(f"{'True Positives (TP)':<25} | {b_met['tp']:>15} | {t_met['tp']:>15}")
        print(f"{'True Negatives (TN)':<25} | {b_met['tn']:>15} | {t_met['tn']:>15}")
        print(f"{'False Positives (FP)':<25} | {b_met['fp']:>15} | {t_met['fp']:>15}")
        print(f"{'False Negatives (FN)':<25} | {b_met['fn']:>15} | {t_met['fn']:>15}")
        print(f"{'Accuracy':<25} | {b_met['accuracy']:>15.4f} | {t_met['accuracy']:>15.4f}")
        print(f"{'Precision':<25} | {b_met['precision']:>15.4f} | {t_met['precision']:>15.4f}")
        print(f"{'Recall (TPR / Detection)':<25} | {b_met['recall']:>15.4f} | {t_met['recall']:>15.4f}")
        print(f"{'False Positive Rate (FPR)':<25} | {b_met['fpr']:>15.4f} | {t_met['fpr']:>15.4f}")
        print(f"{'F1-Score':<25} | {b_met['f1_score']:>15.4f} | {t_met['f1_score']:>15.4f}")

        print("\n[4] CANONICAL BENCHMARK: SCENARIO-WISE DETECTION BREAKDOWN")
        print("-" * 76)
        print(f"{'Scenario':<16} | {'Samples':>7} | {'Result':>10} | {'Rate':>14} | {'Status':>12}")
        print("-" * 68)
        for sc_name, sc_data in scenarios.items():
            if sc_data.get("specificity") is not None and "predicted_normal" in sc_data:
                det_str = f"{sc_data['predicted_normal']}/{sc_data['sample_count']}"
                rate_str = f"{sc_data['specificity'] * 100:.1f}% spec"
                status = sc_data["status"]
            else:
                det_str = f"{sc_data['true_positives']}/{sc_data['sample_count']}"
                rate_str = f"{sc_data['detection_rate'] * 100:.1f}% rec"
                status = sc_data["status"]
            print(f"{sc_name:<16} | {sc_data['sample_count']:>7} | {det_str:>10} | {rate_str:>14} | {status:>12}")

        if challenging_test is not None:
            c_met = challenging_test["overall_metrics"]
            c_scenarios = challenging_test["scenarios"]

            print("\n[5] CHALLENGING BENCHMARK: HELD-OUT TEST PERFORMANCE")
            print("    (Subtle Threats & Borderline Legitimate Activity)")
            print("-" * 76)
            print(f"{'Metric':<28} | {'Challenging Value':>18} | {'Canonical Value':>18}")
            print("-" * 70)
            print(f"{'True Positives (TP)':<28} | {c_met['tp']:>18} | {t_met['tp']:>18}")
            print(f"{'True Negatives (TN)':<28} | {c_met['tn']:>18} | {t_met['tn']:>18}")
            print(f"{'False Positives (FP)':<28} | {c_met['fp']:>18} | {t_met['fp']:>18}")
            print(f"{'False Negatives (FN)':<28} | {c_met['fn']:>18} | {t_met['fn']:>18}")
            print(f"{'Accuracy':<28} | {c_met['accuracy']:>18.4f} | {t_met['accuracy']:>18.4f}")
            print(f"{'Precision':<28} | {c_met['precision']:>18.4f} | {t_met['precision']:>18.4f}")
            print(f"{'Recall (TPR / Detection)':<28} | {c_met['recall']:>18.4f} | {t_met['recall']:>18.4f}")
            print(f"{'False Positive Rate (FPR)':<28} | {c_met['fpr']:>18.4f} | {t_met['fpr']:>18.4f}")
            print(f"{'F1-Score':<28} | {c_met['f1_score']:>18.4f} | {t_met['f1_score']:>18.4f}")

            print("\n[6] CHALLENGING BENCHMARK: SCENARIO-WISE DETECTION BREAKDOWN")
            print("-" * 76)
            print(f"{'Scenario':<24} | {'Type':<12} | {'Samples':>7} | {'Result':>10} | {'Rate':>14} | {'Status':>12}")
            print("-" * 88)
            for sc_name, sc_data in c_scenarios.items():
                if sc_data.get("specificity") is not None and "predicted_normal" in sc_data:
                    sc_type = "Normal (0)"
                    det_str = f"{sc_data['predicted_normal']}/{sc_data['sample_count']}"
                    rate_str = f"{sc_data['specificity'] * 100:.1f}% spec"
                    status = sc_data["status"]
                else:
                    sc_type = "Threat (1)"
                    det_str = f"{sc_data['true_positives']}/{sc_data['sample_count']}"
                    rate_str = f"{sc_data['detection_rate'] * 100:.1f}% rec"
                    status = sc_data["status"]
                print(f"{sc_name:<24} | {sc_type:<12} | {sc_data['sample_count']:>7} | {det_str:>10} | {rate_str:>14} | {status:>12}")

        print("\n[7] HONEST EVALUATION: MODEL WEAKNESSES & STRUGGLING SCENARIOS")
        print("-" * 76)
        all_struggling = list(set(
            report["struggling_scenarios"] +
            report.get("challenging_struggling_scenarios", [])
        ))
        if all_struggling:
            print(" [!] Model struggles with the following subtle or borderline scenarios (detection < 85%):")
            for sc in sorted(all_struggling):
                print(f"     - '{sc}'")
            print(" [*] Operational Takeaway: Subtle/gradual attacks blend into normal cluster density,")
            print("     while heavy legitimate backups/updates produce statistical outlier volume.")
            print("     This demonstrates why deterministic rules and whitelisting remain critical.")
        else:
            print(" [*] Model demonstrated >= 85% detection across all evaluated scenarios.")

        print("\n" + "=" * 76)
        print(" [!] NOTE: Synthetic evaluation baseline is NOT a substitute for live operational data.")
        print("=" * 76 + "\n")

    return report


if __name__ == "__main__":
    import argparse
    import sys

    parser = argparse.ArgumentParser(
        description="Sentinel AI - ML Model Evaluation CLI Entrypoint"
    )
    parser.add_argument(
        "--model-path",
        type=str,
        default=None,
        help="Path to saved model artifact (.joblib). Defaults to configured model path."
    )
    parser.add_argument(
        "--train-if-missing",
        action="store_true",
        help="Train a temporary in-memory model if no saved model artifact exists on disk."
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress formatted console output."
    )
    args = parser.parse_args()

    try:
        run_evaluation_cli(
            model_path=args.model_path,
            train_if_missing=args.train_if_missing,
            verbose=not args.quiet
        )
    except Exception as err:
        print(f"[FATAL] {err}", file=sys.stderr)
        sys.exit(1)
