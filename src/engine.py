from functools import lru_cache
import joblib
import json
import logging
import os
import numpy as np
import pandas as pd
from typing import Dict, List, Any, Optional

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class Engine:
    def __init__(self, models_path: str = "models"):
        self.models_path = models_path
        self.model = None
        self.scaler = None
        self.feature_names = []
        self._loaded = False
        self._warmed_up = False
        self._cache = {}  # Simple cache for repeated calculations

        # simple rule set, unchanged from before
        self.risk_rules = {
            "high_orig_bytes": {"condition": lambda x: float(x.get("orig_bytes", 0)) > 10000, "points": 30, "name": "High origin bytes"},
            "high_packet_counts": {"condition": lambda x: (float(x.get("orig_pkts", 0)) + float(x.get("resp_pkts", 0))) > 100, "points": 20, "name": "High packet count"},
            "icmp_protocol": {"condition": lambda x: str(x.get("proto", "")).upper() == "ICMP", "points": 15, "name": "ICMP protocol"},
            "failed_connection": {"condition": lambda x: str(x.get("conn_state", "")) in ["REJ", "RST", "REJECT", "RESET"], "points": 25, "name": "Failed connection"}
        }

        self._load_artifacts()

        # perform a warmup inference if we successfully loaded features
        if self._loaded:
            self._perform_warmup()
    
    def _load_artifacts(self):
        """Load model, scaler and metadata"""
        try:
            model_path = os.path.join(self.models_path, "isolation_forest.pkl")
            scaler_path = os.path.join(self.models_path, "scaler.pkl")
            metadata_path = os.path.join(self.models_path, "metadata.json")
            
            if os.path.exists(model_path):
                self.model = joblib.load(model_path)
                logger.info(f"Model loaded from {model_path}")
            else:
                logger.warning(f"Model not found at {model_path}")
            
            if os.path.exists(scaler_path):
                self.scaler = joblib.load(scaler_path)
                logger.info(f"Scaler loaded from {scaler_path}")
            else:
                logger.warning(f"Scaler not found at {scaler_path}")
            
            if os.path.exists(metadata_path):
                with open(metadata_path, 'r') as f:
                    metadata = json.load(f)
                    self.feature_names = metadata.get("feature_names", [])
                logger.info(f"Metadata loaded from {metadata_path}, {len(self.feature_names)} features")
                self._loaded = True
            else:
                logger.warning(f"Metadata not found at {metadata_path}")
                
        except Exception as e:
            logger.error(f"Error loading artifacts: {str(e)}")
            raise
    
    def _safe_float(self, value: Any) -> float:
        """Safely convert any value to float, defaulting to 0 on failure"""
        if value is None:
            return 0.0
        if isinstance(value, (int, float)):
            return float(value)
        try:
            return float(str(value).strip()) if str(value).strip() else 0.0
        except (ValueError, TypeError):
            return 0.0
    
    def _extract_features(self, telemetry: Dict[str, Any]) -> pd.DataFrame:
        """Extract and scale features from telemetry data using metadata feature names"""
        if not self.feature_names:
            raise ValueError("No feature names available from metadata")
        
        feature_dict = {}
        proto_val = str(telemetry.get("proto", "")).upper()
        conn_state_val = str(telemetry.get("conn_state", ""))
        missing_features = []
        
        for feature in self.feature_names:
            if feature in telemetry:
                feature_dict[feature] = self._safe_float(telemetry[feature])
            elif feature.startswith("proto_"):
                expected_proto = feature.replace("proto_", "").upper()
                feature_dict[feature] = 1.0 if proto_val == expected_proto else 0.0
            elif feature.startswith("conn_state_"):
                expected_state = feature.replace("conn_state_", "")
                feature_dict[feature] = 1.0 if conn_state_val == expected_state else 0.0
            else:
                feature_dict[feature] = 0.0
                missing_features.append(feature)
        
        if missing_features and len(missing_features) < len(self.feature_names):
            logger.debug(
                f"Filled {len(missing_features)} missing features with 0: {missing_features[:5]}"
            )
        
        features_df = pd.DataFrame([feature_dict])

        try:
            features_df = features_df[self.feature_names]
        except KeyError as e:
            logger.error(f"Feature mismatch while reordering features: {e}")
            rebuilt = pd.DataFrame(0.0, index=[0], columns=self.feature_names)
            for col, value in feature_dict.items():
                if col in rebuilt.columns:
                    rebuilt[col] = value
            features_df = rebuilt

        return features_df
    
    def _calculate_rule_score(self, telemetry: Dict[str, Any]) -> tuple:
        """Calculate rule-based score (higher = more risky) and return score and triggered rules"""
        total_points = 0
        triggered_rules = []
        
        for rule_key, rule_config in self.risk_rules.items():
            try:
                if rule_config["condition"](telemetry):
                    total_points += rule_config["points"]
                    triggered_rules.append(rule_config["name"])
            except Exception as e:
                logger.debug(f"Error evaluating rule {rule_key}: {str(e)}")
        
        rule_score = min(100, total_points)
        return rule_score, triggered_rules
    
    def _sigmoid(self, x: float) -> float:
        """Sigmoid function"""
        if x >= 0:
            return 1.0 / (1.0 + np.exp(-x))
        else:
            exp_x = np.exp(x)
            return exp_x / (1.0 + exp_x)
    
    def _calculate_ml_score(self, telemetry: Dict[str, Any]) -> float:
        """Calculate ML-based anomaly score (0-100, higher = more anomalous)"""
        if self.model is None or self.scaler is None or not self._loaded:
            logger.debug("Model or scaler not available, returning neutral score")
            return 50.0
        
        try:
            if not hasattr(self.model, "decision_function"):
                logger.error("Model does not have decision_function method")
                return 50.0
            
            if self.scaler.n_features_in_ != len(self.feature_names):
                raise ValueError(f"Feature mismatch: scaler expects {self.scaler.n_features_in_} features, metadata has {len(self.feature_names)}")
            
            features_df = self._extract_features(telemetry)
            scaled_features = self.scaler.transform(features_df)
            
            decision_score = self.model.decision_function(scaled_features)[0]
            
            sigmoid_score = self._sigmoid(-decision_score)
            ml_score = sigmoid_score * 100.0
            
            return float(np.clip(ml_score, 0, 100))
            
        except Exception as e:
            logger.error(f"Error calculating ML score: {str(e)}", exc_info=True)
            return 50.0  # Always return a float, never None

    def _calculate_entropy_score(self, telemetry: Dict[str, Any]) -> float:
        """Compute a simple packet-entropy based risk score (0-100).
        Low entropy (i.e. one field dominates) is considered more risky.
        """
        # work with a fixed set of numeric fields
        fields = ["orig_bytes", "resp_bytes", "orig_pkts", "resp_pkts"]
        values = []
        for f in fields:
            values.append(self._safe_float(telemetry.get(f, 0)))
        total = sum(values)
        if total <= 0:
            return 0.0
        probs = [v / total for v in values]
        # Shannon entropy
        entropy = -sum(p * np.log2(p) for p in probs if p > 0)
        max_entropy = np.log2(len(values)) if len(values) > 1 else 1
        normalized = entropy / max_entropy if max_entropy > 0 else 0
        # risk score is higher when entropy is lower
        entropy_score = (1.0 - normalized) * 100.0
        return float(np.clip(entropy_score, 0, 100))

    def _calculate_confidence(self, ml_score: float, rule_score: float, entropy_score: float) -> float:
        """Blend multiple scores into a single confidence metric (0-100).
        Higher value indicates the engine is more confident that the input is
        normal (i.e. inversely related to combined risk).
        """
        combined_risk = (0.5 * ml_score) + (0.3 * rule_score) + (0.2 * entropy_score)
        confidence = 100.0 - combined_risk
        return float(np.clip(confidence, 0, 100))

    def _get_cache_key(self, telemetry: Dict[str, Any]) -> str:
        """Generate a cache key from telemetry data"""
        # Use a subset of fields for caching to avoid too many unique keys
        cache_fields = {
            'proto': telemetry.get('proto', ''),
            'conn_state': telemetry.get('conn_state', ''),
            'orig_bytes': round(self._safe_float(telemetry.get('orig_bytes', 0)), -1),  # Round to nearest 10
            'resp_bytes': round(self._safe_float(telemetry.get('resp_bytes', 0)), -1),
            'orig_pkts': round(self._safe_float(telemetry.get('orig_pkts', 0)), -1),
            'resp_pkts': round(self._safe_float(telemetry.get('resp_pkts', 0)), -1)
        }
        return str(sorted(cache_fields.items()))

    def _perform_warmup(self):
        """Run a dummy inference to prime model/scaler and avoid first-call latency."""
        if self._warmed_up:
            return
        # Create a dummy telemetry with required fields
        dummy = {
            "duration": 1.0,
            "orig_bytes": 1000,
            "resp_bytes": 1000,
            "orig_pkts": 10,
            "resp_pkts": 10,
            "proto": "TCP",
            "conn_state": "SF",
            "device_id": "warmup"
        }
        try:
            _ = self.score_telemetry(dummy)
            logger.info("Warmup inference completed")
        except Exception as e:
            logger.debug(f"Warmup inference failed: {e}")
        finally:
            self._warmed_up = True
    
    def _clear_cache(self):
        """Clear the internal cache"""
        self._cache.clear()
        logger.debug("Cache cleared")
  
    def _format_explanation(self, telemetry: Dict[str, Any], result: Dict[str, Any],
                            feature_deviations: Optional[Dict[str, float]] = None) -> str:
        """Format a human-readable explanation for a scoring result.
        See docs/EXPLAINABILITY.md for the full specification.
        """
        device_id = telemetry.get("device_id", "unknown")
        verdict = result["verdict"]
        trust = result["trust_score"]
        ml = result["ml_score"]
        rule = result["rule_score"]
        entropy = result["entropy_score"]
        confidence = result["confidence"]

        lines = [
            f"[{verdict}] Device: {device_id} | Trust: {trust:.1f}/100 | Confidence: {confidence:.1f}%",
            f"  Breakdown: ML={ml:.1f} (x0.70={ml*0.7:.1f}) | Rule={rule} (x0.20={rule*0.2:.1f}) | Entropy={entropy:.1f} (x0.10={entropy*0.1:.1f})",
        ]

        if result.get("risk_factors"):
            lines.append(f"  Rules triggered: {', '.join(result['risk_factors'])}")

        if result.get("top_features"):
            feat_strs = []
            for feat in result["top_features"]:
                if feature_deviations and feat in feature_deviations:
                    feat_strs.append(f"{feat} ({feature_deviations[feat]:+.1f} sigma)")
                else:
                    feat_strs.append(feat)
            lines.append(f"  Top features: {', '.join(feat_strs)}")

        return " | ".join(lines) if verdict == "NORMAL" else "\n".join(lines)

    def score_telemetry(self, telemetry: Dict[str, Any]) -> Dict[str, Any]:
        """Score a single telemetry record and return comprehensive results.

        Uses metadata-driven feature extraction with safe defaults for missing
        fields, computes entropy/confidence, and adds explanation fields.

        Returns a dict containing:
            trust_score     (float 0-100): Overall trust. Higher = more trustworthy.
            ml_score        (float 0-100): ML anomaly score. Higher = more anomalous.
            rule_score      (float 0-100): Heuristic rule penalty sum.
            entropy_score   (float 0-100): Entropy-based risk. Low entropy = high score.
            confidence      (float 0-100): Confidence that traffic is normal.
            verdict         (str): NORMAL | SUSPICIOUS | RISKY | ANOMALY
            risk_factors    (list[str]): Names of triggered heuristic rules.
            top_features    (list[str]): Top 3 features by deviation from training mean.
            risk_score_breakdown (dict): Individual sub-score components.
            from_cache      (bool): Whether result was served from cache.

        Scoring formula:
            risk  = 0.70 * ml_score + 0.20 * rule_score + 0.10 * entropy_score
            trust = 100 - risk
        See docs/EXPLAINABILITY.md for detailed worked examples.
        """
        logger.debug(f"Scoring telemetry for device={telemetry.get('device_id', 'unknown')}")

        try:
            # Check cache first for repeated similar requests
            cache_key = self._get_cache_key(telemetry)
            if cache_key in self._cache:
                cached_result = self._cache[cache_key].copy()
                cached_result["from_cache"] = True
                logger.debug("Returning cached result")
                return cached_result

            rule_score, risk_factors = self._calculate_rule_score(telemetry)
            ml_score = self._calculate_ml_score(telemetry)
            entropy_score = self._calculate_entropy_score(telemetry)

            # composite risk using new entropy component
            risk_score = (0.7 * ml_score) + (0.2 * rule_score) + (0.1 * entropy_score)
            risk_score = float(np.clip(risk_score, 0, 100))

            trust_score = 100.0 - risk_score

            confidence = self._calculate_confidence(ml_score, rule_score, entropy_score)

            # compute top features by deviation from mean (using scaler)
            top_feats = []
            feature_deviations = {}
            try:
                features_df = self._extract_features(telemetry)
                if self.scaler is not None:
                    scaled = self.scaler.transform(features_df)[0]
                    abs_vals = np.abs(scaled)
                    # pick top 3 features
                    idxs = np.argsort(abs_vals)[::-1][:3]
                    top_feats = [self.feature_names[i] for i in idxs]
                    # record deviation magnitudes for explainability
                    for i in idxs:
                        feature_deviations[self.feature_names[i]] = float(scaled[i])
            except Exception as e:
                logger.debug(f"Error computing top features: {e}")
                top_feats = []

            result = {
                "trust_score": round(trust_score, 2),
                "rule_score": rule_score,
                "ml_score": round(ml_score, 2),
                "entropy_score": round(entropy_score, 2),
                "confidence": round(confidence, 2),
                "risk_factors": risk_factors,
                "top_features": top_feats,
                "risk_score_breakdown": {
                    "ml_score": round(ml_score, 2),
                    "rule_score": rule_score,
                    "entropy_score": round(entropy_score, 2)
                }
            }

            if trust_score > 70:
                result["verdict"] = "NORMAL"
            elif trust_score > 50:
                result["verdict"] = "SUSPICIOUS"
            elif trust_score > 30:
                result["verdict"] = "RISKY"
            else:
                result["verdict"] = "ANOMALY"

            # Cache the result (with a reasonable cache size)
            if len(self._cache) > 100:  # Prevent unbounded growth
                # Remove oldest item (simple approach)
                self._cache.pop(next(iter(self._cache)))
            self._cache[cache_key] = result.copy()
            result["from_cache"] = False

            # Structured explainability logging
            explanation = self._format_explanation(telemetry, result, feature_deviations)
            if result["verdict"] in ("ANOMALY", "RISKY"):
                logger.warning(f"ALERT: {explanation}")
            elif result["verdict"] == "SUSPICIOUS":
                logger.info(f"WATCH: {explanation}")
            else:
                logger.debug(f"OK: {explanation}")

            return result

        except Exception as e:
            logger.error(f"Error scoring telemetry: {str(e)}", exc_info=True)
            # Return a default result instead of None
            return {
                "trust_score": 50.0,
                "rule_score": 0,
                "ml_score": 50.0,
                "entropy_score": 50.0,
                "confidence": 50.0,
                "risk_factors": ["Error in processing"],
                "top_features": [],
                "risk_score_breakdown": {
                    "ml_score": 50.0,
                    "rule_score": 0,
                    "entropy_score": 50.0
                },
                "verdict": "UNCERTAIN"
            }

_engine_instance = None

def load_engine(models_path: str = "models") -> Engine:
    """Factory function to create and return an Engine instance (singleton)"""
    global _engine_instance
    if _engine_instance is None:
        _engine_instance = Engine(models_path)
    return _engine_instance

def score_telemetry(telemetry_dict: Dict[str, Any]) -> Dict[str, Any]:
    """Convenience function for scoring telemetry with default engine"""
    engine = load_engine()
    return engine.score_telemetry(telemetry_dict)