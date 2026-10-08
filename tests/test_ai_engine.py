"""
Unit tests for AI engine module.
"""
import os
# Set environment variables before importing the app modules
os.environ['DEBUG'] = 'true'
os.environ['JWT_SECRET_KEY'] = '0123456789abcdef0123456789abcdef'  # 32 chars
os.environ['AGENT_API_KEY'] = 'test-agent-key'
# Add other required environment variables if needed
os.environ['DATABASE_URL'] = 'sqlite:///./test.db'
os.environ['CORS_ORIGINS'] = '["http://localhost:3000"]'
os.environ['ANOMALY_CONTAMINATION'] = '0.1'
os.environ['MIN_TRAINING_SAMPLES'] = '10'

import sys
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'backend'))

import pytest
from unittest.mock import Mock, patch
import numpy as np

from ai_engine import AnomalyDetector, anomaly_detector


class TestAnomalyDetector:
    """Test the anomaly detection engine."""

    def setup_method(self):
        """Set up test fixtures."""
        self.detector = AnomalyDetector()

    def test_init(self):
        """Test detector initialization."""
        assert self.detector.model is None
        assert self.detector.is_trained is False
        assert self.detector.feature_names == [
            "failed_attempts",
            "login_frequency",
            "ip_activity_rate",
            "hour_of_day",
        ]

    def test_build_model(self):
        """Test model building."""
        model = self.detector._build_model()
        assert model is not None
        assert hasattr(model, 'predict')
        assert hasattr(model, 'fit')

    @pytest.mark.parametrize("data_count,expected_result", [
        (5, False),  # Less than MIN_TRAINING_SAMPLES
        (10, True),  # Equal to MIN_TRAINING_SAMPLES
        (15, True),  # More than MIN_TRAINING_SAMPLES
    ])
    def test_train_insufficient_data(self, data_count, expected_result):
        """Test training with insufficient data."""
        data = [{"failed_attempts": 0, "login_frequency": 0,
                 "ip_activity_rate": 0, "hour_of_day": 12}] * data_count

        result = self.detector.train(data)
        assert result == expected_result

        if expected_result:
            assert self.detector.is_trained is True
            assert self.detector.model is not None
        else:
            assert self.detector.is_trained is False
            assert self.detector.model is None

    def test_train_sufficient_data(self):
        """Test training with sufficient data."""
        # Create training data
        data = []
        for i in range(15):  # More than MIN_TRAINING_SAMPLES
            data.append({
                "failed_attempts": i % 3,
                "login_frequency": float(i % 5),
                "ip_activity_rate": float(i % 10),
                "hour_of_day": i % 24
            })

        result = self.detector.train(data)
        assert result is True
        assert self.detector.is_trained is True
        assert self.detector.model is not None

    def test_extract_features(self):
        """Test feature extraction."""
        data = [
            {"failed_attempts": 2, "login_frequency": 5.0,
             "ip_activity_rate": 10.0, "hour_of_day": 14},
            {"failed_attempts": 0, "login_frequency": 0.0,
             "ip_activity_rate": 0.0, "hour_of_day": 2}
        ]

        features = self.detector._extract_features(data)
        expected = np.array([
            [2.0, 5.0, 10.0, 14.0],
            [0.0, 0.0, 0.0, 2.0]
        ])

        np.testing.assert_array_equal(features, expected)

    def test_extract_features_with_missing_values(self):
        """Test feature extraction with missing values."""
        data = [
            {"failed_attempts": 2},  # Missing other fields
            {"login_frequency": 5.0},  # Missing other fields
        ]

        features = self.detector._extract_features(data)
        expected = np.array([
            [2.0, 0.0, 0.0, 12.0],  # Defaults: 0, 0, 0, 12 (hour_of_day default)
            [0.0, 5.0, 0.0, 12.0]
        ])

        np.testing.assert_array_equal(features, expected)

    def test_predict_before_training(self):
        """Test prediction before model training."""
        log_entry = {
            "failed_attempts": 5,
            "login_frequency": 10.0,
            "ip_activity_rate": 20.0,
            "hour_of_day": 2
        }

        # Should fall back to rule-based detection
        result = self.detector.predict(log_entry)
        # With failed_attempts >= 5, should return True (anomaly)
        assert result is True

    def test_predict_after_training(self):
        """Test prediction after model training."""
        # Train the model first
        training_data = []
        for i in range(20):
            training_data.append({
                "failed_attempts": i % 3,
                "login_frequency": float(i % 5),
                "ip_activity_rate": float(i % 10),
                "hour_of_day": i % 24
            })

        self.detector.train(training_data)
        assert self.detector.is_trained is True

        # Test normal log entry
        normal_log = {
            "failed_attempts": 0,
            "login_frequency": 1.0,
            "ip_activity_rate": 2.0,
            "hour_of_day": 14
        }

        result = self.detector.predict(normal_log)
        # Should return boolean
        assert isinstance(result, bool)

        # Test anomalous log entry
        anomalous_log = {
            "failed_attempts": 10,
            "login_frequency": 50.0,
            "ip_activity_rate": 100.0,
            "hour_of_day": 3
        }

        result = self.detector.predict(anomalous_log)
        assert isinstance(result, bool)

    def test_predict_batch(self):
        """Test batch prediction."""
        logs = [
            {"failed_attempts": 0, "login_frequency": 1.0,
             "ip_activity_rate": 2.0, "hour_of_day": 14},
            {"failed_attempts": 5, "login_frequency": 10.0,
             "ip_activity_rate": 20.0, "hour_of_day": 2}
        ]

        # Test before training (should use rule-based)
        results = self.detector.predict_batch(logs)
        assert len(results) == 2
        assert all(isinstance(r, bool) for r in results)
        # Second log should be anomalous (failed_attempts >= 5)
        assert results[0] is False  # Normal
        assert results[1] is True   # Anomalous

    def test_predict_batch_after_training(self):
        """Test batch prediction after training."""
        # Train the model
        training_data = []
        for i in range(20):
            training_data.append({
                "failed_attempts": i % 3,
                "login_frequency": float(i % 5),
                "ip_activity_rate": float(i % 10),
                "hour_of_day": i % 24
            })

        self.detector.train(training_data)

        # Test batch prediction
        logs = [
            {"failed_attempts": 0, "login_frequency": 1.0,
             "ip_activity_rate": 2.0, "hour_of_day": 14},
            {"failed_attempts": 5, "login_frequency": 10.0,
             "ip_activity_rate": 20.0, "hour_of_day": 2}
        ]

        results = self.detector.predict_batch(logs)
        assert len(results) == 2
        assert all(isinstance(r, bool) for r in results)

    def test_get_anomaly_score_before_training(self):
        """Test getting anomaly score before training."""
        log_entry = {
            "failed_attempts": 0,
            "login_frequency": 0.0,
            "ip_activity_rate": 0.0,
            "hour_of_day": 12
        }

        score = self.detector.get_anomaly_score(log_entry)
        assert score == 0.0  # Should return 0.0 when not trained

    def test_get_anomaly_score_after_training(self):
        """Test getting anomaly score after training."""
        # Train the model
        training_data = []
        for i in range(20):
            training_data.append({
                "failed_attempts": i % 3,
                "login_frequency": float(i % 5),
                "ip_activity_rate": float(i % 10),
                "hour_of_day": i % 24
            })

        self.detector.train(training_data)

        # Test getting anomaly score
        log_entry = {
            "failed_attempts": 0,
            "login_frequency": 1.0,
            "ip_activity_rate": 2.0,
            "hour_of_day": 14
        }

        score = self.detector.get_anomaly_score(log_entry)
        assert isinstance(score, float)
        # Score should be a float (negative values indicate more anomalous)

    def test_rule_based_detection(self):
        """Test rule-based detection logic."""
        # Test case: failed_attempts >= 5
        log_entry = {"failed_attempts": 5, "login_frequency": 0,
                     "ip_activity_rate": 0, "hour_of_day": 12}
        assert self.detector._rule_based_detection(log_entry) is True

        # Test case: login_frequency > 20
        log_entry = {"failed_attempts": 0, "login_frequency": 25,
                     "ip_activity_rate": 0, "hour_of_day": 12}
        assert self.detector._rule_based_detection(log_entry) is True

        # Test case: ip_activity_rate > 50
        log_entry = {"failed_attempts": 0, "login_frequency": 0,
                     "ip_activity_rate": 60, "hour_of_day": 12}
        assert self.detector._rule_based_detection(log_entry) is True

        # Test case: night time with failed attempts
        log_entry = {"failed_attempts": 2, "login_frequency": 0,
                     "ip_activity_rate": 0, "hour_of_day": 3}
        assert self.detector._rule_based_detection(log_entry) is True

        # Test case: normal log
        log_entry = {"failed_attempts": 1, "login_frequency": 5,
                     "ip_activity_rate": 10, "hour_of_day": 14}
        assert self.detector._rule_based_detection(log_entry) is False

    def test_singleton_instance(self):
        """Test that anomaly_detector is a singleton instance."""
        assert isinstance(anomaly_detector, AnomalyDetector)
        # Should be an instance of AnomalyDetector
        assert type(anomaly_detector) == AnomalyDetector


if __name__ == "__main__":
    pytest.main([__file__, "-v"])