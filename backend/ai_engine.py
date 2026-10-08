"""
AI-SIEM Guardian — AI Anomaly Detection Engine
Uses Isolation Forest to detect anomalous log patterns in real time.
"""

import logging
import numpy as np
from sklearn.ensemble import IsolationForest
from typing import Optional, List, Dict

from config import settings

logger = logging.getLogger(__name__)


class AnomalyDetector:
    """
    Wraps scikit-learn's Isolation Forest for cybersecurity anomaly detection.
    
    Features used:
      - failed_attempts   : number of failed login attempts
      - login_frequency   : logins per hour from this user
      - ip_activity_rate  : requests per minute from this IP
      - hour_of_day       : hour extracted from timestamp (0-23)
    """

    def __init__(self):
        self.model: Optional[IsolationForest] = None
        self.is_trained: bool = False
        self.feature_names = [
            "failed_attempts",
            "login_frequency",
            "ip_activity_rate",
            "hour_of_day",
        ]

    def _build_model(self) -> IsolationForest:
        """Create a fresh Isolation Forest instance."""
        return IsolationForest(
            contamination=settings.ANOMALY_CONTAMINATION,
            n_estimators=100,
            random_state=42,
            n_jobs=-1,
        )

    def train(self, data: List[Dict]) -> bool:
        """
        Train (or retrain) the model on historical log data.
        Each dict in `data` must have the four feature keys.
        Returns True if training succeeded.
        """
        if len(data) < settings.MIN_TRAINING_SAMPLES:
            logger.warning(
                f"Not enough data to train ({len(data)} < {settings.MIN_TRAINING_SAMPLES})"
            )
            return False

        X = self._extract_features(data)
        self.model = self._build_model()
        self.model.fit(X)
        self.is_trained = True
        logger.info(f"Anomaly detector trained on {len(data)} samples")
        return True

    def predict(self, log_entry: Dict) -> bool:
        """
        Predict whether a single log entry is anomalous.
        Returns True if anomaly, False if normal.
        If the model hasn't been trained yet, fall back to rule-based detection.
        """
        if not self.is_trained or self.model is None:
            return self._rule_based_detection(log_entry)

        X = self._extract_features([log_entry])
        prediction = self.model.predict(X)
        # Isolation Forest: -1 = anomaly, 1 = normal
        return bool(prediction[0] == -1)

    def predict_batch(self, logs: List[Dict]) -> List[bool]:
        """Predict anomalies for a batch of log entries."""
        if not logs:
            return []
        if not self.is_trained or self.model is None:
            return [self._rule_based_detection(log) for log in logs]

        X = self._extract_features(logs)
        predictions = self.model.predict(X)
        return [bool(p == -1) for p in predictions]

    def _extract_features(self, data: List[Dict]) -> np.ndarray:
        """Convert list of log dicts into a feature matrix."""
        features = []
        for entry in data:
            features.append([
                float(entry.get("failed_attempts", 0)),
                float(entry.get("login_frequency", 0)),
                float(entry.get("ip_activity_rate", 0)),
                float(entry.get("hour_of_day", 12)),
            ])
        return np.array(features)

    def _rule_based_detection(self, log_entry: Dict) -> bool:
        """
        Fallback heuristic when the ML model isn't trained yet.
        Flags entries with high failed attempts or unusual activity rates.
        """
        failed = log_entry.get("failed_attempts", 0)
        freq = log_entry.get("login_frequency", 0)
        ip_rate = log_entry.get("ip_activity_rate", 0)
        hour = log_entry.get("hour_of_day", 12)

        # Simple rule-based thresholds
        if failed >= 5:
            return True
        if freq > 20:
            return True
        if ip_rate > 50:
            return True
        if (hour < 4 or hour > 23) and failed >= 2:
            return True
        return False

    def get_anomaly_score(self, log_entry: Dict) -> float:
        """Return the raw anomaly score (lower = more anomalous)."""
        if not self.is_trained or self.model is None:
            return 0.0
        X = self._extract_features([log_entry])
        return float(self.model.score_samples(X)[0])


# Global singleton
anomaly_detector = AnomalyDetector()
