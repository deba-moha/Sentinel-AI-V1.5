"""
Sentinel AI - Synthetic Training & Evaluation Data Generator (Phase 2 & Phase 3)
Generates realistic, diverse, and reproducible baseline training data and
labeled multi-scenario anomaly datasets across the 9 canonical features.

DISCLAIMER:
Synthetic training data is a development baseline designed for reproducible model
benchmarking and architecture validation. It is NOT a substitute for real operational
normal-traffic data collected from live production network environments.
"""
from typing import Any, Dict, List, Optional, Tuple
import numpy as np
from backend.app.ml.config import ML_FEATURE_NAMES, ml_config
from backend.app.ml.preprocessing import validate_feature_matrix


def generate_normal_training_data(
    n_samples: int = 250,
    seed: Optional[int] = None
) -> np.ndarray:
    """
    Generates a reproducible 2D NumPy array representing normal baseline security activity.

    Characteristics of normal activity:
    - Moderate total events (5 to 45 events per window).
    - Very few or zero failed authentications (0 to 2 typos, never brute-force floods).
    - Regular successful authentications (0 to 4 logins).
    - Modest IP diversity (1 to 8 internal source hosts, 1 to 2 destination targets).
    - Standard port access (1 to 3 distinct destination ports like 80, 443, 53).
    - Realistic frequency (0.1 to 1.8 requests/second) and inter-event intervals (0.5 to 15s).
    - Normal payload volume (250 to 1,500 bytes per event).

    Guarantees:
    - Shape (n_samples, 9), dtype np.float64.
    - Columns strictly match ML_FEATURE_NAMES in sequence.
    - Uses NumPy and standard Python only (zero Pandas).
    - No attack patterns (brute-force, port-scan, DDoS, or extreme volume spikes).
    """
    if n_samples <= 0:
        return np.empty((0, len(ML_FEATURE_NAMES)), dtype=np.float64)

    random_seed = seed if seed is not None else ml_config.isolation_forest.random_state
    rng = np.random.default_rng(seed=random_seed)

    rows: List[List[float]] = []
    failed_auth_choices = np.array([0, 1, 2])
    failed_auth_probs = np.array([0.80, 0.16, 0.04])

    for _ in range(n_samples):
        total_events = int(rng.integers(5, 45))
        failed_auth = int(rng.choice(failed_auth_choices, p=failed_auth_probs))
        successful_auth = int(rng.integers(0, 5))
        max_sources = max(1, min(total_events, 8))
        unique_sources = int(rng.integers(1, max_sources + 1))
        unique_dests = int(rng.integers(1, 3))
        unique_ports = int(rng.integers(1, 4))

        window_duration = float(rng.uniform(20.0, 60.0))
        event_frequency = round(total_events / window_duration, 4)
        avg_time_interval = round(window_duration / max(1, total_events - 1), 4)

        bytes_per_event = float(rng.uniform(250.0, 1500.0))
        network_volume = round(float(total_events * bytes_per_event), 2)

        row = [
            float(total_events),
            float(failed_auth),
            float(successful_auth),
            float(unique_sources),
            float(unique_dests),
            float(unique_ports),
            float(event_frequency),
            float(avg_time_interval),
            float(network_volume)
        ]
        rows.append(row)

    matrix = np.array(rows, dtype=np.float64)
    validate_feature_matrix(matrix, expected_features=len(ML_FEATURE_NAMES))
    return matrix


def generate_brute_force_samples(
    n_samples: int = 25,
    seed: Optional[int] = None
) -> np.ndarray:
    """
    Generates synthetic samples modeling repeated authentication failure attacks.
    Key signatures: high failed_auth_count, single source IP, single destination port.
    """
    if n_samples <= 0:
        return np.empty((0, len(ML_FEATURE_NAMES)), dtype=np.float64)

    rng = np.random.default_rng(seed=seed)
    rows: List[List[float]] = []

    for _ in range(n_samples):
        total_events = float(rng.integers(35, 120))
        failed_auth = float(rng.integers(30, int(total_events) + 1))
        row = [
            total_events,
            failed_auth,
            0.0,                  # Successful auth is 0 during brute force
            1.0,                  # Single attacking source IP
            1.0,                  # Targeted destination host
            1.0,                  # Target port (e.g., SSH 22 or RDP 3389)
            round(float(rng.uniform(4.0, 25.0)), 4),   # High request frequency
            round(float(rng.uniform(0.01, 0.15)), 4),  # Very short interval
            round(float(total_events * rng.uniform(300.0, 800.0)), 2)
        ]
        rows.append(row)

    matrix = np.array(rows, dtype=np.float64)
    validate_feature_matrix(matrix, expected_features=len(ML_FEATURE_NAMES))
    return matrix


def generate_port_scan_samples(
    n_samples: int = 25,
    seed: Optional[int] = None
) -> np.ndarray:
    """
    Generates synthetic samples modeling network port scanning reconnaissance.
    Key signatures: high unique_dest_ports, single source IP, elevated probe frequency.
    """
    if n_samples <= 0:
        return np.empty((0, len(ML_FEATURE_NAMES)), dtype=np.float64)

    rng = np.random.default_rng(seed=seed)
    rows: List[List[float]] = []

    for _ in range(n_samples):
        total_events = float(rng.integers(60, 250))
        distinct_ports = float(rng.integers(25, min(120, int(total_events))))
        row = [
            total_events,
            0.0,
            0.0,
            1.0,                  # Single scanner source IP
            1.0,                  # Targeted destination host
            distinct_ports,       # Probing dozens of distinct ports
            round(float(rng.uniform(8.0, 35.0)), 4),   # Rapid scanning frequency
            round(float(rng.uniform(0.01, 0.09)), 4),  # Sub-tenth second intervals
            round(float(total_events * rng.uniform(64.0, 256.0)), 2)  # Lightweight SYN packets
        ]
        rows.append(row)

    matrix = np.array(rows, dtype=np.float64)
    validate_feature_matrix(matrix, expected_features=len(ML_FEATURE_NAMES))
    return matrix


def generate_ddos_samples(
    n_samples: int = 25,
    seed: Optional[int] = None
) -> np.ndarray:
    """
    Generates synthetic samples modeling distributed denial of service floods.
    Key signatures: huge total_events, high unique_source_ips, massive event_frequency.
    """
    if n_samples <= 0:
        return np.empty((0, len(ML_FEATURE_NAMES)), dtype=np.float64)

    rng = np.random.default_rng(seed=seed)
    rows: List[List[float]] = []

    for _ in range(n_samples):
        total_events = float(rng.integers(400, 2500))
        unique_sources = float(rng.integers(30, 200))
        row = [
            total_events,
            0.0,
            0.0,
            unique_sources,       # Botnet sources hitting single target
            1.0,                  # Targeted destination service
            1.0,                  # Typically port 80/443
            round(float(rng.uniform(40.0, 200.0)), 4),  # Enormous request frequency
            round(float(rng.uniform(0.001, 0.02)), 4),  # Millisecond intervals
            round(float(total_events * rng.uniform(1024.0, 4096.0)), 2)
        ]
        rows.append(row)

    matrix = np.array(rows, dtype=np.float64)
    validate_feature_matrix(matrix, expected_features=len(ML_FEATURE_NAMES))
    return matrix


def generate_data_burst_samples(
    n_samples: int = 25,
    seed: Optional[int] = None
) -> np.ndarray:
    """
    Generates synthetic samples modeling volumetric data bursts or exfiltration spikes.
    Key signatures: massive network_traffic_volume with elevated single-host activity.
    """
    if n_samples <= 0:
        return np.empty((0, len(ML_FEATURE_NAMES)), dtype=np.float64)

    rng = np.random.default_rng(seed=seed)
    rows: List[List[float]] = []

    for _ in range(n_samples):
        total_events = float(rng.integers(120, 400))
        volume = float(rng.uniform(15_000_000.0, 80_000_000.0))  # 15MB to 80MB
        row = [
            total_events,
            0.0,
            1.0,                  # Occasional authenticated channel
            1.0,                  # Single source host
            1.0,                  # Single destination
            1.0,                  # Typically standard transfer port (443/22)
            round(float(rng.uniform(10.0, 35.0)), 4),
            round(float(rng.uniform(0.02, 0.10)), 4),
            round(volume, 2)
        ]
        rows.append(row)

    matrix = np.array(rows, dtype=np.float64)
    validate_feature_matrix(matrix, expected_features=len(ML_FEATURE_NAMES))
    return matrix


def generate_synthetic_anomaly_samples(
    n_samples: int = 15,
    seed: Optional[int] = 1337
) -> np.ndarray:
    """
    Generates a mixed set of synthetic anomalies across all four attack types.
    Maintained for backward compatibility with Phase 2 tests.
    """
    if n_samples <= 0:
        return np.empty((0, len(ML_FEATURE_NAMES)), dtype=np.float64)

    rng = np.random.default_rng(seed=seed)
    samples_per_type = max(1, n_samples // 4)
    remainder = n_samples - (samples_per_type * 4)

    bf = generate_brute_force_samples(samples_per_type + remainder, seed=int(rng.integers(1, 100000)))
    ps = generate_port_scan_samples(samples_per_type, seed=int(rng.integers(1, 100000)))
    ddos = generate_ddos_samples(samples_per_type, seed=int(rng.integers(1, 100000)))
    burst = generate_data_burst_samples(samples_per_type, seed=int(rng.integers(1, 100000)))

    matrix = np.vstack([bf, ps, ddos, burst])
    # Deterministic shuffle to mix patterns
    shuffled_indices = rng.permutation(len(matrix))
    return matrix[shuffled_indices]


def generate_labeled_dataset(
    n_normal: int = 100,
    n_per_anomaly: int = 25,
    seed: Optional[int] = None
) -> Tuple[np.ndarray, np.ndarray, List[str]]:
    """
    Generates a structured, labeled evaluation dataset containing normal traffic and
    the four canonical threat scenarios:
    - Normal baseline
    - Brute force
    - Port scan
    - DDoS
    - Data burst

    Returns:
        X: (N, 9) feature matrix
        y: (N,) binary ground truth array (0 = Normal, 1 = Anomaly)
        scenarios: List of scenario name strings matching each row
    """
    rng = np.random.default_rng(seed=seed)

    s_norm = int(rng.integers(1, 100000))
    s_bf = int(rng.integers(1, 100000))
    s_ps = int(rng.integers(1, 100000))
    s_ddos = int(rng.integers(1, 100000))
    s_burst = int(rng.integers(1, 100000))

    X_normal = generate_normal_training_data(n_samples=n_normal, seed=s_norm)
    X_bf = generate_brute_force_samples(n_samples=n_per_anomaly, seed=s_bf)
    X_ps = generate_port_scan_samples(n_samples=n_per_anomaly, seed=s_ps)
    X_ddos = generate_ddos_samples(n_samples=n_per_anomaly, seed=s_ddos)
    X_burst = generate_data_burst_samples(n_samples=n_per_anomaly, seed=s_burst)

    X = np.vstack([X_normal, X_bf, X_ps, X_ddos, X_burst])

    y = np.concatenate([
        np.zeros(len(X_normal), dtype=int),
        np.ones(len(X_bf) + len(X_ps) + len(X_ddos) + len(X_burst), dtype=int)
    ])

    scenarios = (
        ["normal"] * len(X_normal) +
        ["brute_force"] * len(X_bf) +
        ["port_scan"] * len(X_ps) +
        ["ddos"] * len(X_ddos) +
        ["data_burst"] * len(X_burst)
    )

    return X, y, scenarios


def generate_evaluation_splits(
    n_train_normal: int = 250,
    n_val_normal: int = 100,
    n_val_per_anomaly: int = 25,
    n_test_normal: int = 100,
    n_test_per_anomaly: int = 25,
    base_seed: int = 42,
    include_challenging: bool = True,
    n_challenging_per_scenario: int = 25
) -> Dict[str, Any]:
    """
    Generates strictly segregated Training, Validation, and Test datasets.

    Strict Leakage Prevention:
    - Train: Normal baseline only (seed=base_seed).
    - Validation: Normal + 4 canonical anomaly scenarios for threshold tuning (seed=base_seed + 101).
    - Test: Completely held-out Normal + 4 canonical anomaly scenarios (seed=base_seed + 202).
    - Challenging Validation: 4 borderline normal + 4 subtle anomaly scenarios (seed=base_seed + 303).
    - Challenging Test: Completely held-out challenging scenarios (seed=base_seed + 404).

    Returns dictionary with keys 'train', 'validation', 'test'
    (and 'challenging_validation', 'challenging_test' if include_challenging=True).
    """
    # 1. Training set (normal baseline only)
    X_train = generate_normal_training_data(n_samples=n_train_normal, seed=base_seed)

    # 2. Canonical Validation set (held out from training, used for threshold tuning)
    X_val, y_val, scenarios_val = generate_labeled_dataset(
        n_normal=n_val_normal,
        n_per_anomaly=n_val_per_anomaly,
        seed=base_seed + 101
    )

    # 3. Canonical Test set (completely held out from training AND threshold tuning)
    X_test, y_test, scenarios_test = generate_labeled_dataset(
        n_normal=n_test_normal,
        n_per_anomaly=n_test_per_anomaly,
        seed=base_seed + 202
    )

    splits: Dict[str, Any] = {
        "train": {
            "X": X_train,
            "y": np.zeros(len(X_train), dtype=int),
            "scenarios": ["normal"] * len(X_train),
            "seed": base_seed
        },
        "validation": {
            "X": X_val,
            "y": y_val,
            "scenarios": scenarios_val,
            "seed": base_seed + 101
        },
        "test": {
            "X": X_test,
            "y": y_test,
            "scenarios": scenarios_test,
            "seed": base_seed + 202
        }
    }

    if include_challenging:
        X_c_val, y_c_val, scenarios_c_val = generate_challenging_labeled_dataset(
            n_per_scenario=n_challenging_per_scenario,
            seed=base_seed + 303
        )
        X_c_test, y_c_test, scenarios_c_test = generate_challenging_labeled_dataset(
            n_per_scenario=n_challenging_per_scenario,
            seed=base_seed + 404
        )
        splits["challenging_validation"] = {
            "X": X_c_val,
            "y": y_c_val,
            "scenarios": scenarios_c_val,
            "seed": base_seed + 303
        }
        splits["challenging_test"] = {
            "X": X_c_test,
            "y": y_c_test,
            "scenarios": scenarios_c_test,
            "seed": base_seed + 404
        }

    return splits


# =====================================================================
# Subtle Anomalies & Borderline Legitimate Normal Scenarios (Correction 2)
# =====================================================================

def generate_low_and_slow_auth_samples(
    n_samples: int = 25,
    seed: Optional[int] = None
) -> np.ndarray:
    """
    Generates synthetic samples modeling subtle, low-and-slow authentication attacks.
    Key signatures: slightly elevated failed authentications (3 to 7) dispersed across
    normal time intervals, designed to blend with legitimate password typos and evade
    high-frequency rate alarms. Ground truth: Anomaly (y = 1).
    """
    if n_samples <= 0:
        return np.empty((0, len(ML_FEATURE_NAMES)), dtype=np.float64)

    rng = np.random.default_rng(seed=seed)
    rows: List[List[float]] = []

    for _ in range(n_samples):
        total_events = float(rng.integers(12, 35))
        failed_auth = float(rng.integers(3, min(8, int(total_events))))
        successful_auth = float(rng.integers(0, 2))
        unique_sources = float(rng.integers(1, 3))
        unique_dests = 1.0
        unique_ports = float(rng.integers(1, 3))

        event_freq = round(float(rng.uniform(0.15, 0.75)), 4)
        avg_interval = round(float(rng.uniform(1.5, 6.5)), 4)
        volume = round(float(total_events * rng.uniform(300.0, 900.0)), 2)

        row = [
            total_events,
            failed_auth,
            successful_auth,
            unique_sources,
            unique_dests,
            unique_ports,
            event_freq,
            avg_interval,
            volume
        ]
        rows.append(row)

    matrix = np.array(rows, dtype=np.float64)
    validate_feature_matrix(matrix, expected_features=len(ML_FEATURE_NAMES))
    return matrix


def generate_gradual_port_scan_samples(
    n_samples: int = 25,
    seed: Optional[int] = None
) -> np.ndarray:
    """
    Generates synthetic samples modeling slow, low-intensity reconnaissance scans.
    Key signatures: probes a small handful of distinct ports (5 to 12) rather than
    hundreds of ports, at deliberate human-like intervals. Ground truth: Anomaly (y = 1).
    """
    if n_samples <= 0:
        return np.empty((0, len(ML_FEATURE_NAMES)), dtype=np.float64)

    rng = np.random.default_rng(seed=seed)
    rows: List[List[float]] = []

    for _ in range(n_samples):
        total_events = float(rng.integers(18, 50))
        distinct_ports = float(rng.integers(5, min(13, int(total_events))))
        row = [
            total_events,
            0.0,
            0.0,
            1.0,
            1.0,
            distinct_ports,
            round(float(rng.uniform(0.3, 1.4)), 4),
            round(float(rng.uniform(0.8, 3.5)), 4),
            round(float(total_events * rng.uniform(80.0, 300.0)), 2)
        ]
        rows.append(row)

    matrix = np.array(rows, dtype=np.float64)
    validate_feature_matrix(matrix, expected_features=len(ML_FEATURE_NAMES))
    return matrix


def generate_moderate_traffic_burst_samples(
    n_samples: int = 25,
    seed: Optional[int] = None
) -> np.ndarray:
    """
    Generates synthetic samples modeling moderate data exfiltration or spike traffic.
    Key signatures: traffic volume between 1.2 MB and 4.5 MB with moderate event counts,
    much lower than catastrophic 80MB dumps. Ground truth: Anomaly (y = 1).
    """
    if n_samples <= 0:
        return np.empty((0, len(ML_FEATURE_NAMES)), dtype=np.float64)

    rng = np.random.default_rng(seed=seed)
    rows: List[List[float]] = []

    for _ in range(n_samples):
        total_events = float(rng.integers(40, 110))
        volume = float(rng.uniform(1_200_000.0, 4_500_000.0))
        row = [
            total_events,
            0.0,
            1.0,
            1.0,
            1.0,
            float(rng.integers(1, 3)),
            round(float(rng.uniform(1.8, 5.0)), 4),
            round(float(rng.uniform(0.2, 0.6)), 4),
            round(volume, 2)
        ]
        rows.append(row)

    matrix = np.array(rows, dtype=np.float64)
    validate_feature_matrix(matrix, expected_features=len(ML_FEATURE_NAMES))
    return matrix


def generate_subtle_recon_samples(
    n_samples: int = 25,
    seed: Optional[int] = None
) -> np.ndarray:
    """
    Generates synthetic samples modeling subtle multi-source or multi-destination reconnaissance.
    Key signatures: small cluster of source IPs probing a handful of internal endpoints.
    Ground truth: Anomaly (y = 1).
    """
    if n_samples <= 0:
        return np.empty((0, len(ML_FEATURE_NAMES)), dtype=np.float64)

    rng = np.random.default_rng(seed=seed)
    rows: List[List[float]] = []

    for _ in range(n_samples):
        total_events = float(rng.integers(25, 60))
        unique_sources = float(rng.integers(3, 7))
        unique_dests = float(rng.integers(2, 5))
        unique_ports = float(rng.integers(3, 6))
        failed_auth = float(rng.integers(1, 3))
        row = [
            total_events,
            failed_auth,
            0.0,
            unique_sources,
            unique_dests,
            unique_ports,
            round(float(rng.uniform(0.5, 2.0)), 4),
            round(float(rng.uniform(0.5, 2.0)), 4),
            round(float(total_events * rng.uniform(400.0, 1200.0)), 2)
        ]
        rows.append(row)

    matrix = np.array(rows, dtype=np.float64)
    validate_feature_matrix(matrix, expected_features=len(ML_FEATURE_NAMES))
    return matrix


def generate_admin_activity_samples(
    n_samples: int = 25,
    seed: Optional[int] = None
) -> np.ndarray:
    """
    Generates synthetic samples modeling legitimate administrative maintenance activity.
    Characteristics: elevated event count, multiple destination endpoints and management ports
    (SSH, RDP, HTTPS), multiple successful authentications. Non-malicious (y = 0).
    """
    if n_samples <= 0:
        return np.empty((0, len(ML_FEATURE_NAMES)), dtype=np.float64)

    rng = np.random.default_rng(seed=seed)
    rows: List[List[float]] = []

    for _ in range(n_samples):
        total_events = float(rng.integers(35, 75))
        failed_auth = float(rng.choice([0, 1, 2], p=[0.70, 0.25, 0.05]))
        successful_auth = float(rng.integers(3, 8))
        unique_sources = float(rng.integers(1, 3))
        unique_dests = float(rng.integers(3, 7))
        unique_ports = float(rng.integers(3, 6))
        row = [
            total_events,
            failed_auth,
            successful_auth,
            unique_sources,
            unique_dests,
            unique_ports,
            round(float(rng.uniform(0.8, 2.2)), 4),
            round(float(rng.uniform(0.4, 1.4)), 4),
            round(float(rng.uniform(30_000.0, 200_000.0)), 2)
        ]
        rows.append(row)

    matrix = np.array(rows, dtype=np.float64)
    validate_feature_matrix(matrix, expected_features=len(ML_FEATURE_NAMES))
    return matrix


def generate_backup_burst_samples(
    n_samples: int = 25,
    seed: Optional[int] = None
) -> np.ndarray:
    """
    Generates synthetic samples modeling scheduled enterprise backup traffic bursts.
    Characteristics: high network volume (2 MB to 10 MB) concentrated on a single backup
    server and port, normal auth. Non-malicious (y = 0).
    """
    if n_samples <= 0:
        return np.empty((0, len(ML_FEATURE_NAMES)), dtype=np.float64)

    rng = np.random.default_rng(seed=seed)
    rows: List[List[float]] = []

    for _ in range(n_samples):
        total_events = float(rng.integers(50, 160))
        volume = float(rng.uniform(2_000_000.0, 10_000_000.0))
        row = [
            total_events,
            0.0,
            float(rng.integers(1, 3)),
            1.0,
            1.0,
            1.0,
            round(float(rng.uniform(1.5, 4.5)), 4),
            round(float(rng.uniform(0.2, 0.7)), 4),
            round(volume, 2)
        ]
        rows.append(row)

    matrix = np.array(rows, dtype=np.float64)
    validate_feature_matrix(matrix, expected_features=len(ML_FEATURE_NAMES))
    return matrix


def generate_software_update_samples(
    n_samples: int = 25,
    seed: Optional[int] = None
) -> np.ndarray:
    """
    Generates synthetic samples modeling operating system or package manager updates.
    Characteristics: moderate-to-high download volume (1 MB to 6 MB), querying 2 to 4
    CDN repository mirrors on standard HTTPS ports. Non-malicious (y = 0).
    """
    if n_samples <= 0:
        return np.empty((0, len(ML_FEATURE_NAMES)), dtype=np.float64)

    rng = np.random.default_rng(seed=seed)
    rows: List[List[float]] = []

    for _ in range(n_samples):
        total_events = float(rng.integers(40, 110))
        volume = float(rng.uniform(1_000_000.0, 6_000_000.0))
        row = [
            total_events,
            0.0,
            1.0,
            1.0,
            float(rng.integers(2, 5)),
            float(rng.integers(1, 3)),
            round(float(rng.uniform(1.0, 3.2)), 4),
            round(float(rng.uniform(0.3, 1.0)), 4),
            round(volume, 2)
        ]
        rows.append(row)

    matrix = np.array(rows, dtype=np.float64)
    validate_feature_matrix(matrix, expected_features=len(ML_FEATURE_NAMES))
    return matrix


def generate_heavy_workstation_samples(
    n_samples: int = 25,
    seed: Optional[int] = None
) -> np.ndarray:
    """
    Generates synthetic samples modeling active developer/analyst workstation traffic.
    Characteristics: diverse internal connections (database, git, api), volume up to 600 KB.
    Non-malicious (y = 0).
    """
    if n_samples <= 0:
        return np.empty((0, len(ML_FEATURE_NAMES)), dtype=np.float64)

    rng = np.random.default_rng(seed=seed)
    rows: List[List[float]] = []

    for _ in range(n_samples):
        total_events = float(rng.integers(30, 70))
        volume = float(rng.uniform(80_000.0, 600_000.0))
        row = [
            total_events,
            float(rng.choice([0, 1], p=[0.85, 0.15])),
            float(rng.integers(2, 5)),
            1.0,
            float(rng.integers(2, 5)),
            float(rng.integers(2, 5)),
            round(float(rng.uniform(0.6, 2.0)), 4),
            round(float(rng.uniform(0.5, 1.8)), 4),
            round(volume, 2)
        ]
        rows.append(row)

    matrix = np.array(rows, dtype=np.float64)
    validate_feature_matrix(matrix, expected_features=len(ML_FEATURE_NAMES))
    return matrix


def generate_challenging_labeled_dataset(
    n_per_scenario: int = 25,
    seed: Optional[int] = None
) -> Tuple[np.ndarray, np.ndarray, List[str]]:
    """
    Generates a structured, challenging evaluation dataset containing subtle anomaly threats
    and borderline legitimate normal activity across 8 distinct scenarios:

    Borderline Normal (y = 0):
    - admin_activity
    - backup_burst
    - software_updates
    - heavy_workstation

    Subtle Anomalies (y = 1):
    - low_and_slow_auth
    - gradual_port_scan
    - moderate_traffic_burst
    - subtle_recon

    Returns:
        X: (N, 9) feature matrix
        y: (N,) binary ground truth array (0 = Normal, 1 = Anomaly)
        scenarios: List of scenario name strings matching each row
    """
    rng = np.random.default_rng(seed=seed)

    s_admin = int(rng.integers(1, 100000))
    s_backup = int(rng.integers(1, 100000))
    s_update = int(rng.integers(1, 100000))
    s_workstation = int(rng.integers(1, 100000))

    s_low_auth = int(rng.integers(1, 100000))
    s_grad_scan = int(rng.integers(1, 100000))
    s_mod_burst = int(rng.integers(1, 100000))
    s_sub_recon = int(rng.integers(1, 100000))

    X_admin = generate_admin_activity_samples(n_samples=n_per_scenario, seed=s_admin)
    X_backup = generate_backup_burst_samples(n_samples=n_per_scenario, seed=s_backup)
    X_update = generate_software_update_samples(n_samples=n_per_scenario, seed=s_update)
    X_workstation = generate_heavy_workstation_samples(n_samples=n_per_scenario, seed=s_workstation)

    X_low_auth = generate_low_and_slow_auth_samples(n_samples=n_per_scenario, seed=s_low_auth)
    X_grad_scan = generate_gradual_port_scan_samples(n_samples=n_per_scenario, seed=s_grad_scan)
    X_mod_burst = generate_moderate_traffic_burst_samples(n_samples=n_per_scenario, seed=s_mod_burst)
    X_sub_recon = generate_subtle_recon_samples(n_samples=n_per_scenario, seed=s_sub_recon)

    X = np.vstack([
        X_admin, X_backup, X_update, X_workstation,
        X_low_auth, X_grad_scan, X_mod_burst, X_sub_recon
    ])

    normal_count = len(X_admin) + len(X_backup) + len(X_update) + len(X_workstation)
    anomaly_count = len(X_low_auth) + len(X_grad_scan) + len(X_mod_burst) + len(X_sub_recon)

    y = np.concatenate([
        np.zeros(normal_count, dtype=int),
        np.ones(anomaly_count, dtype=int)
    ])

    scenarios = (
        ["admin_activity"] * len(X_admin) +
        ["backup_burst"] * len(X_backup) +
        ["software_updates"] * len(X_update) +
        ["heavy_workstation"] * len(X_workstation) +
        ["low_and_slow_auth"] * len(X_low_auth) +
        ["gradual_port_scan"] * len(X_grad_scan) +
        ["moderate_traffic_burst"] * len(X_mod_burst) +
        ["subtle_recon"] * len(X_sub_recon)
    )

    return X, y, scenarios
