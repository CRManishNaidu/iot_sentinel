# IoT Sentinel Setup and Execution Guide

## 1. Setting Up the Virtual Environment

**Step 1: Navigate to the project directory**
```bash
cd iot_sentinel
```

**Step 2: Create a virtual environment**
```bash
python3 -m venv venv
```

**Step 3: Activate the virtual environment**

- **Windows**
```bash
venv\Scripts\activate
```

- **Linux/macOS**
```bash
source venv/bin/activate
```

**Step 4: Upgrade pip**
```bash
pip install --upgrade pip
```

**Step 5: Install all required packages**
```bash
pip install fastapi uvicorn streamlit pandas numpy scikit-learn joblib plotly matplotlib seaborn requests websocket-client websockets
```

---

## 2. Running the Data Pipeline

Execute the data processing pipeline:
```bash
python src/data_pipeline.py
```

> This will prepare the datasets for model training.

---

## 3. Model Training

Train the Isolation Forest model:
```bash
python src/train.py
```

> This will generate the trained model files used for anomaly detection.

---

## 4. Running the Application

Start the full application by clicking the `start_all.bat` file in the project root.