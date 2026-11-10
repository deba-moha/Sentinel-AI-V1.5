"""
Sentinel AI - Machine Learning Package (Phase 1, 2 & 3)
Provides feature extraction, preprocessing, synthetic baseline generation,
Isolation Forest anomaly detection, model persistence, and evaluation metrics.

Pure NumPy and Scikit-learn architecture without Pandas.
"""
from backend.app.ml.config import (
    ML_FEATURE_NAMES,
    DEFAULT_MODEL_DIR,
    DEFAULT_MODEL_PATH,
    IsolationForestConfig,
    MLConfig,
    ml_config
)
from backend.app.ml.features import (
    extract_features_from_logs,
    extract_features_by_source_ip,
    extract_features_batch
)
from backend.app.ml.preprocessing import (
    clean_numerical_value,
    preprocess_feature_dict,
    preprocess_feature_batch,
    preprocess_to_records,
    validate_feature_matrix
)
from backend.app.ml.model import (
    IsolationForestModel
)
from backend.app.ml.model_store import (
    save_model,
    load_model,
    model_exists,
    get_model_metadata,
    ModelStoreError,
    ModelNotFoundError,
    ModelValidationError
)
from backend.app.ml.training_data import (
    generate_normal_training_data,
    generate_synthetic_anomaly_samples,
    generate_brute_force_samples,
    generate_port_scan_samples,
    generate_ddos_samples,
    generate_data_burst_samples,
    generate_labeled_dataset,
    generate_evaluation_splits,
    generate_low_and_slow_auth_samples,
    generate_gradual_port_scan_samples,
    generate_moderate_traffic_burst_samples,
    generate_subtle_recon_samples,
    generate_admin_activity_samples,
    generate_backup_burst_samples,
    generate_software_update_samples,
    generate_heavy_workstation_samples,
    generate_challenging_labeled_dataset
)
from backend.app.ml.train import (
    train_model
)
from backend.app.ml.evaluation import (
    EvaluationMetrics,
    calculate_metrics,
    evaluate_dataset,
    evaluate_scenarios,
    tune_threshold,
    run_comprehensive_evaluation
)

__all__ = [
    # Config
    "ML_FEATURE_NAMES",
    "DEFAULT_MODEL_DIR",
    "DEFAULT_MODEL_PATH",
    "IsolationForestConfig",
    "MLConfig",
    "ml_config",
    # Features
    "extract_features_from_logs",
    "extract_features_by_source_ip",
    "extract_features_batch",
    # Preprocessing
    "clean_numerical_value",
    "preprocess_feature_dict",
    "preprocess_feature_batch",
    "preprocess_to_records",
    "validate_feature_matrix",
    # Model
    "IsolationForestModel",
    # Store
    "save_model",
    "load_model",
    "model_exists",
    "get_model_metadata",
    "ModelStoreError",
    "ModelNotFoundError",
    "ModelValidationError",
    # Training Data
    "generate_normal_training_data",
    "generate_synthetic_anomaly_samples",
    "generate_brute_force_samples",
    "generate_port_scan_samples",
    "generate_ddos_samples",
    "generate_data_burst_samples",
    "generate_labeled_dataset",
    "generate_evaluation_splits",
    "generate_low_and_slow_auth_samples",
    "generate_gradual_port_scan_samples",
    "generate_moderate_traffic_burst_samples",
    "generate_subtle_recon_samples",
    "generate_admin_activity_samples",
    "generate_backup_burst_samples",
    "generate_software_update_samples",
    "generate_heavy_workstation_samples",
    "generate_challenging_labeled_dataset",
    # Training Interface
    "train_model",
    # Evaluation
    "EvaluationMetrics",
    "calculate_metrics",
    "evaluate_dataset",
    "evaluate_scenarios",
    "tune_threshold",
    "run_comprehensive_evaluation",
]
