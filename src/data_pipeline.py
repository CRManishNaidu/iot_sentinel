import pandas as pd
import numpy as np
import os
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def load_conn_log(file_path):
    """Load conn.log.labeled file efficiently."""
    logging.info(f"Loading file: {file_path}")
    
    # Find the #fields line to get column names
    fields_line = None
    with open(file_path, 'r') as f:
        for line in f:
            stripped = line.strip()
            if stripped.startswith('#fields'):
                fields_line = stripped
                break
    
    if fields_line is None:
        raise ValueError(f"No #fields line found in {file_path}")
    
    # Extract column names from #fields line
    column_names = fields_line.replace('#fields', '').strip().split('\t')
    
    # Check if the last column contains multiple fields with spaces
    if column_names and ' ' in column_names[-1] and 'label' in column_names[-1].lower():
        last_column = column_names.pop()
        # Split by whitespace to get individual columns
        split_columns = last_column.split()
        column_names.extend(split_columns)
        logging.info(f"Split last column '{last_column}' into: {split_columns}")
    
    # Handle duplicate column names by making them unique
    unique_columns = []
    seen = {}
    for col in column_names:
        if col in seen:
            seen[col] += 1
            unique_columns.append(f"{col}_{seen[col]}")
        else:
            seen[col] = 0
            unique_columns.append(col)
    
    logging.info(f"Found {len(unique_columns)} columns: {unique_columns}")
    
    # Read the file using regex whitespace separator to handle mixed tabs and spaces
    df = pd.read_csv(
        file_path,
        sep=r'\s+',
        engine='python',
        comment='#',
        header=None,
        names=unique_columns,
        dtype=str,
        on_bad_lines='warn'
    )
    
    logging.info(f"Loaded {len(df)} rows from {file_path}")
    return df

def extract_features(df):
    """Extract required features from the dataframe."""
    # Define possible column name variations with common duplicates
    column_mappings = {
        'duration': ['duration', 'dur'],
        'orig_bytes': ['orig_bytes', 'orig_ip_bytes'],
        'resp_bytes': ['resp_bytes', 'resp_ip_bytes'],
        'orig_pkts': ['orig_pkts', 'orig_packets'],
        'resp_pkts': ['resp_pkts', 'resp_packets'],
        'proto': ['proto'],
        'conn_state': ['conn_state'],
        'label': ['label', 'Label']
    }
    
    selected_columns = {}
    for target, possibilities in column_mappings.items():
        for col in possibilities:
            if col in df.columns:
                selected_columns[target] = col
                logging.info(f"Mapped {target} to column: {col}")
                break
    
    # Check if we found all required columns
    required_cols = ['duration', 'orig_bytes', 'resp_bytes', 'orig_pkts', 'resp_pkts', 'proto', 'conn_state', 'label']
    missing_cols = [col for col in required_cols if col not in selected_columns]
    if missing_cols:
        logging.warning(f"Missing columns: {missing_cols}")
        logging.warning(f"Available columns: {list(df.columns)}")
    
    # Extract the columns that were found
    found_cols = list(selected_columns.values())
    extracted_df = df[found_cols].copy() if found_cols else pd.DataFrame()
    
    # Rename columns to standard names
    extracted_df.columns = list(selected_columns.keys())

    for col in required_cols:
        if col not in extracted_df.columns:
            extracted_df[col] = np.nan if col in {'proto', 'conn_state', 'label'} else 0.0
    
    return extracted_df

def clean_data(df):
    """Clean and preprocess the data."""
    if df.empty:
        return df
    
    # Avoid pandas downcasting warnings by using masked replacement.
    df = df.mask(df.eq('-') | df.eq('(empty)'))
    
    # Convert numeric columns
    numeric_cols = ['duration', 'orig_bytes', 'resp_bytes', 'orig_pkts', 'resp_pkts']
    for col in numeric_cols:
        if col in df.columns:
            df[col] = pd.to_numeric(df[col], errors='coerce')
    
    # Fill NaN with 0 for numeric columns and downcast for memory efficiency.
    for col in numeric_cols:
        if col in df.columns:
            df[col] = pd.to_numeric(df[col].fillna(0), downcast='float')
    
    # Drop rows where duration is NaN (critical for feature engineering)
    if 'duration' in df.columns:
        initial_rows = len(df)
        df = df.dropna(subset=['duration'])
        if len(df) < initial_rows:
            logging.info(f"Dropped {initial_rows - len(df)} rows with missing duration")

    for col in ['proto', 'conn_state', 'label']:
        if col in df.columns:
            df[col] = df[col].astype('category')
    
    return df

def engineer_features(df):
    """Create engineered features."""
    if df.empty:
        return df

    required_numeric = ['orig_bytes', 'resp_bytes', 'duration', 'orig_pkts', 'resp_pkts']
    for col in required_numeric:
        if col not in df.columns:
            logging.warning(f"Missing column '{col}' for feature engineering; defaulting to 0")
            df[col] = 0.0
    
    # Calculate bytes_per_second
    df['total_bytes'] = df['orig_bytes'] + df['resp_bytes']
    df['bytes_per_second'] = df['total_bytes'] / (df['duration'] + 0.0001)
    
    # Calculate packet ratio
    df['packet_ratio'] = df['orig_pkts'] / (df['resp_pkts'] + 1)
    
    # Drop intermediate column
    df = df.drop(columns=['total_bytes'])
    
    return df

def process_labels(df):
    """Process labels to binary classification based on actual label values."""
    if df.empty or 'label' not in df.columns:
        logging.warning("No label column found. All rows will be labeled based on source.")
        return df
    
    # Debug: Print unique raw labels before any processing
    raw_labels = df["label"].unique()[:20]
    logging.info(f"Unique raw labels (first 20): {raw_labels}")
    print("Unique raw labels:", raw_labels)
    
    # Normalize label column
    df["label"] = df["label"].astype(str).str.strip().str.lower()
    
    # Create binary label
    df["binary_label"] = df["label"].apply(
        lambda x: 1 if "malicious" in x else (0 if "benign" in x else None)
    )
    
    # Print distribution
    print("Binary label distribution:")
    print(df["binary_label"].value_counts(dropna=False))
    
    logging.info(f"Binary label distribution: {df['binary_label'].value_counts(dropna=False).to_dict()}")
    
    # Log original label distribution
    logging.info(f"Normalized label distribution: {df['label'].value_counts().to_dict()}")
    
    # Drop original label column
    df = df.drop(columns=['label'])
    
    return df

def encode_categorical_after_merge(df, categorical_cols=None):
    """One-hot encode categorical columns AFTER datasets are combined."""
    if df.empty:
        return df
    
    if categorical_cols is None:
        categorical_cols = ['proto', 'conn_state']
    
    # Check which categorical columns exist
    cols_to_encode = [col for col in categorical_cols if col in df.columns]
    
    if not cols_to_encode:
        logging.warning(f"No categorical columns found to encode. Available: {list(df.columns)}")
        return df
    
    logging.info(f"Encoding columns: {cols_to_encode}")
    
    encode_data = df[cols_to_encode].fillna('unknown').astype('category')
    encoded_df = pd.get_dummies(
        encode_data,
        columns=cols_to_encode,
        prefix=cols_to_encode,
        sparse=True,
        dtype=np.uint8
    )

    other_cols = df.drop(columns=cols_to_encode)
    df = pd.concat([other_cols, encoded_df], axis=1)

    added_cols = [c for c in encoded_df.columns if c not in cols_to_encode]
    logging.info(f"Added {len(added_cols)} encoded columns")
    return df

def main():
    """Main execution function."""
    # File paths
    honeypot_path = r'C:\Users\manis\Documents\Projects\5 - IOT\iot_sentinel\data\raw\CTU-Honeypot-Capture-4-1\bro\conn.log.labeled'
    malware_path = r'C:\Users\manis\Documents\Projects\5 - IOT\iot_sentinel\data\raw\CTU-IoT-Malware-Capture-1-1\bro\conn.log.labeled'
    
    # Output path
    output_dir = r'C:\Users\manis\Documents\Projects\5 - IOT\iot_sentinel\data\processed'
    os.makedirs(output_dir, exist_ok=True)
    output_path = os.path.join(output_dir, 'iot23_processed.csv')
    
    try:
        # Load datasets
        logging.info("=" * 50)
        logging.info("STEP 1: Loading datasets")
        logging.info("=" * 50)
        
        honeypot_raw = load_conn_log(honeypot_path)
        malware_raw = load_conn_log(malware_path)
        
        # Extract features
        logging.info("\n" + "=" * 50)
        logging.info("STEP 2: Extracting features")
        logging.info("=" * 50)
        
        honeypot_extracted = extract_features(honeypot_raw)
        malware_extracted = extract_features(malware_raw)
        
        logging.info(f"Honeypot extracted shape: {honeypot_extracted.shape}")
        logging.info(f"Malware extracted shape: {malware_extracted.shape}")
        
        # Clean data
        logging.info("\n" + "=" * 50)
        logging.info("STEP 3: Cleaning data")
        logging.info("=" * 50)
        
        honeypot_clean = clean_data(honeypot_extracted)
        malware_clean = clean_data(malware_extracted)
        
        logging.info(f"Honeypot clean shape: {honeypot_clean.shape}")
        logging.info(f"Malware clean shape: {malware_clean.shape}")
        
        # Engineer features
        logging.info("\n" + "=" * 50)
        logging.info("STEP 4: Engineering features")
        logging.info("=" * 50)
        
        honeypot_features = engineer_features(honeypot_clean)
        malware_features = engineer_features(malware_clean)
        
        # Add source information to help with labeling if needed
        honeypot_features['_source'] = 'honeypot'
        malware_features['_source'] = 'malware'
        
        # Combine datasets BEFORE encoding
        logging.info("\n" + "=" * 50)
        logging.info("STEP 5: Combining datasets")
        logging.info("=" * 50)
        
        combined_df = pd.concat([honeypot_features, malware_features], ignore_index=True)
        logging.info(f"Combined dataset shape: {combined_df.shape}")
        
        # Process labels based on actual values
        logging.info("\n" + "=" * 50)
        logging.info("STEP 6: Processing labels")
        logging.info("=" * 50)
        
        combined_df = process_labels(combined_df)
        
        # Check if we have any rows with binary_label already set
        if 'binary_label' not in combined_df.columns:
            logging.info("No label column found. Using source information for labeling.")
            # Use source as fallback for labeling
            combined_df['binary_label'] = (combined_df['_source'] == 'malware').astype(int)
            logging.info(f"Label distribution from source: {combined_df['binary_label'].value_counts().to_dict()}")
        
        # Remove temporary source column
        if '_source' in combined_df.columns:
            combined_df = combined_df.drop(columns=['_source'])
        
        # One-hot encode categorical columns AFTER combining
        logging.info("\n" + "=" * 50)
        logging.info("STEP 7: Encoding categorical features (after merge)")
        logging.info("=" * 50)
        
        combined_df = encode_categorical_after_merge(combined_df)
        
        # Shuffle final dataset
        logging.info("\n" + "=" * 50)
        logging.info("STEP 8: Shuffling final dataset")
        logging.info("=" * 50)
        
        combined_df = combined_df.sample(frac=1, random_state=42).reset_index(drop=True)
        
        # Final statistics
        logging.info("\n" + "=" * 50)
        logging.info("FINAL DATASET STATISTICS")
        logging.info("=" * 50)
        logging.info(f"Original honeypot rows: {len(honeypot_raw)}")
        logging.info(f"Original malware rows: {len(malware_raw)}")
        logging.info(f"Final dataset shape: {combined_df.shape}")
        logging.info(f"Final columns: {list(combined_df.columns)}")
        
        if 'binary_label' in combined_df.columns:
            label_counts = combined_df['binary_label'].value_counts()
            logging.info(f"\nLabel distribution:")
            logging.info(f"Benign (0): {label_counts.get(0, 0)}")
            logging.info(f"Malicious (1): {label_counts.get(1, 0)}")
        
        # Save to CSV
        logging.info("\n" + "=" * 50)
        logging.info("STEP 9: Saving processed data")
        logging.info("=" * 50)
        
        combined_df.to_csv(output_path, index=False)
        logging.info(f"Successfully saved to: {output_path}")
        
        if os.path.exists(output_path):
            file_size_mb = os.path.getsize(output_path) / (1024 * 1024)
            logging.info(f"File size: {file_size_mb:.2f} MB")
        
    except Exception as e:
        logging.error(f"Error in data pipeline: {str(e)}")
        import traceback
        traceback.print_exc()
        raise

if __name__ == "__main__":
    main()
