@echo off
setlocal enabledelayedexpansion

:: Set console to UTF-8 for emoji support
chcp 65001 > nul

echo ========================================
echo    IoT Sentinel - Start All Components
echo ========================================
echo.

:: Get the directory where this batch file is located
set "SCRIPT_DIR=%~dp0"
set "SCRIPT_DIR=%SCRIPT_DIR:~0,-1%"
set "PROJECT_ROOT=%SCRIPT_DIR%"

echo Project root: %PROJECT_ROOT%
echo.

:: Check if venv exists
if not exist "%PROJECT_ROOT%\venv\" (
    echo ERROR: Virtual environment not found!
    echo Please run setup steps in README.md first.
    pause
    exit /b 1
)

:: Activate virtual environment for the main process
call "%PROJECT_ROOT%\venv\Scripts\activate.bat"

:: Check if required directories exist
if not exist "%PROJECT_ROOT%\data\processed" (
    echo Creating data directories...
    mkdir "%PROJECT_ROOT%\data\processed" 2>nul
)

if not exist "%PROJECT_ROOT%\models" (
    echo Creating models directory...
    mkdir "%PROJECT_ROOT%\models" 2>nul
)

:: Step 1: Check if processed data exists, if not run data pipeline
echo.
echo ========================================
echo STEP 1: Checking data pipeline
echo ========================================

if not exist "%PROJECT_ROOT%\data\processed\iot23_processed.csv" (
    echo Processed data not found. Running data pipeline...
    echo.
    start "Data Pipeline" /D "%PROJECT_ROOT%" cmd /k "call venv\Scripts\activate.bat && python src/data_pipeline.py && echo. && echo Data pipeline completed! && echo Press any key to continue... && pause > nul"
    echo Waiting for data pipeline to complete...
    echo Please wait for the data pipeline window to finish, then press any key here...
    pause
) else (
    echo Processed data found at: data\processed\iot23_processed.csv
)

:: Step 2: Check if model exists, if not run training
echo.
echo ========================================
echo STEP 2: Checking trained model
echo ========================================

if not exist "%PROJECT_ROOT%\models\isolation_forest.pkl" (
    echo Trained model not found. Running model training...
    echo.
    start "Model Training" /D "%PROJECT_ROOT%" cmd /k "call venv\Scripts\activate.bat && python src/train.py && echo. && echo Model training completed! && echo Press any key to continue... && pause > nul"
    echo Waiting for model training to complete...
    echo Please wait for the training window to finish, then press any key here...
    pause
) else (
    echo Trained model found at: models\isolation_forest.pkl
)

:: Step 3: Start FastAPI Server
echo.
echo ========================================
echo STEP 3: Starting FastAPI Server
echo ========================================
echo Starting FastAPI Server on port 8000...
echo.

:: Check if port 8000 is already in use
netstat -ano | find ":8000" > nul
if %errorlevel% equ 0 (
    echo WARNING: Port 8000 might be in use. Trying to start anyway...
)

start "FastAPI Server" /D "%PROJECT_ROOT%" cmd /k "call venv\Scripts\activate.bat && echo [FastAPI] Starting server... && uvicorn src.api_server:app --reload --host 0.0.0.0 --port 8000"

:: Wait for server to initialize
timeout /t 5 /nobreak > nul

:: Check if server started successfully
echo Checking if FastAPI server is responding...
curl -s http://localhost:8000/health > nul
if %errorlevel% equ 0 (
    echo ✅ FastAPI server is running
) else (
    echo ⚠️ FastAPI server might not be responding yet
)

:: Step 4: Start Streamlit Dashboard
echo.
echo ========================================
echo STEP 4: Starting Streamlit Dashboard
echo ========================================
echo Starting Streamlit Dashboard on port 8501...
echo.

:: Check if port 8501 is already in use
netstat -ano | find ":8501" > nul
if %errorlevel% equ 0 (
    echo WARNING: Port 8501 might be in use. Trying to start anyway...
)

start "Streamlit Dashboard" /D "%PROJECT_ROOT%" cmd /k "call venv\Scripts\activate.bat && echo [Streamlit] Starting dashboard... && streamlit run src/dashboard.py"

:: Wait for dashboard to initialize
timeout /t 5 /nobreak > nul

:: Step 5: Start Traffic Simulator
echo.
echo ========================================
echo STEP 5: Starting Traffic Simulator
echo ========================================
echo Starting Traffic Simulator...
echo.

start "Traffic Simulator" /D "%PROJECT_ROOT%" cmd /k "call venv\Scripts\activate.bat && echo [Simulator] Starting traffic generation... && python src/traffic_simulator.py --mode demo"

:: Step 6: Open browsers
echo.
echo ========================================
echo All components started!
echo ========================================
echo.
echo 📍 FastAPI Server: http://localhost:8000
echo 📍 FastAPI Docs: http://localhost:8000/api/docs
echo 📍 Streamlit Dashboard: http://localhost:8501
echo.
echo Project location: %PROJECT_ROOT%
echo.
echo Opening FastAPI docs in browser...
timeout /t 2 > nul
start http://localhost:8000/api/docs

echo Opening Streamlit dashboard in browser...
timeout /t 2 > nul
start http://localhost:8501

echo.
echo ========================================
echo ℹ️  Control Instructions:
echo ========================================
echo.
echo - FastAPI Server: Close its window to stop the API
echo - Streamlit Dashboard: Close its window to stop the dashboard
echo - Traffic Simulator: Press Ctrl+C in its window to stop
echo.
echo To stop all components, close all the opened windows.
echo.
echo Press any key to open Windows Task Manager (for cleanup if needed)...
pause > nul

:: Optional: Open Task Manager for easy cleanup
start taskmgr

exit /b 0
