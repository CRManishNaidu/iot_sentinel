import logging
import json
import pandas as pd
import joblib
from pathlib import Path
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def main():
    """Main training pipeline for IoT anomaly detection."""
    
    # Define paths using pathlib
    current_dir = Path(__file__).parent
    data_path = current_dir / ".." / "data" / "processed" / "iot23_processed.csv"
    model_dir = current_dir / ".." / "models"
    
    # Create model directory if it doesn't exist
    model_dir.mkdir(parents=True, exist_ok=True)
    
    # Step 1: Load CSV using pandas
    logger.info(f"Loading dataset from {data_path}")
    try:
        df = pd.read_csv(data_path)
        logger.info(f"Successfully loaded dataset with shape: {df.shape}")
    except FileNotFoundError:
        logger.error(f"Dataset not found at {data_path}")
        raise
    
    # Remove label column if present (unsupervised learning)
    if "binary_label" in df.columns:
        logger.info("Dropping binary_label column for unsupervised training")
        df = df.drop(columns=["binary_label"])
    
    # Step 2: Keep only numeric columns
    logger.info("Selecting numeric features")
    numeric_df = df.select_dtypes(include=["number"])
    
    non_numeric_count = len(df.columns) - len(numeric_df.columns)
    if non_numeric_count > 0:
        logger.info(f"Dropped {non_numeric_count} non-numeric columns")
        logger.debug(f"Non-numeric columns: {set(df.columns) - set(numeric_df.columns)}")
    
    # Drop rows with NaN values
    initial_rows = len(numeric_df)
    numeric_df = numeric_df.dropna()
    rows_dropped = initial_rows - len(numeric_df)
    if rows_dropped > 0:
        logger.info(f"Dropped {rows_dropped} rows with NaN values")
    
    # Validate dataframe is not empty
    if numeric_df.empty:
        logger.error("DataFrame is empty after processing. Cannot train model.")
        raise ValueError("No valid data available for training")
    
    # Store feature names and count for metadata
    feature_names = numeric_df.columns.tolist()
    n_features = len(feature_names)
    logger.info(f"Using {n_features} features for training with {len(numeric_df)} samples")
    
    # Step 3: Scale features using StandardScaler
    logger.info("Scaling features with StandardScaler")
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(numeric_df)
    logger.info("Feature scaling completed")
    
    # Step 4: Train IsolationForest
    logger.info("Training IsolationForest model")
    logger.info("Parameters: n_estimators=150, contamination=0.01, random_state=42, n_jobs=-1")
    
    model = IsolationForest(
        n_estimators=150,
        contamination=0.01,
        random_state=42,
        n_jobs=-1,
        warm_start=False
    )
    
    model.fit(X_scaled)
    logger.info("Model training completed")
    
    # Compute and log anomaly ratio
    preds = model.predict(X_scaled)
    anomaly_ratio = (preds == -1).mean()
    logger.info(f"Anomaly ratio on training data: {anomaly_ratio:.4f} (expected: 0.01)")
    
    # Step 5: Save scaler and model
    scaler_path = model_dir / "scaler.pkl"
    model_path = model_dir / "isolation_forest.pkl"
    
    logger.info(f"Saving scaler to {scaler_path}")
    joblib.dump(scaler, scaler_path)
    
    logger.info(f"Saving model to {model_path}")
    joblib.dump(model, model_path)
    
    # Step 6: Save metadata JSON
    metadata = {
        "n_features": n_features,
        "feature_names": feature_names,
        "contamination": 0.01,
        "n_estimators": 150,
        "training_samples": len(numeric_df),
        "anomaly_ratio_training": float(anomaly_ratio)
    }
    
    metadata_path = model_dir / "metadata.json"
    logger.info(f"Saving metadata to {metadata_path}")
    
    with open(metadata_path, 'w') as f:
        json.dump(metadata, f, indent=2)
    
    logger.info("Training pipeline completed successfully")
    logger.info(f"Model artifacts saved to {model_dir}")

if __name__ == "__main__":
    main()