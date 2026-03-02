"""
IoT Sentinel - Enterprise SOC Dashboard (Enterprise Edition)
Production-grade, real-time network intrusion detection with comprehensive monitoring.
"""

import streamlit as st
import pandas as pd
import plotly.graph_objects as go
from datetime import datetime, timedelta
from collections import deque, defaultdict
from typing import Dict, List, Optional, Any, Set
from dataclasses import dataclass, field
import threading
import queue
import json
import time
import random
import websocket
import numpy as np
from streamlit_autorefresh import st_autorefresh
import logging
from logging.handlers import RotatingFileHandler
import csv
import io
import atexit
import sys
import os

# =============================================================================
# WINDOWS CONSOLE UTF-8 FIX
# =============================================================================

# Fix Windows console encoding for emoji support
if sys.platform == 'win32':
    # Force UTF-8 encoding for console output
    if hasattr(sys.stdout, 'reconfigure'):
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
        sys.stderr.reconfigure(encoding='utf-8', errors='replace')
    
    # Set console code page to UTF-8
    if os.name == 'nt':
        try:
            os.system('chcp 65001 > nul')
        except:
            pass



# =============================================================================
# CONFIGURATION
# =============================================================================

@dataclass(frozen=True)
class APIConfig:
    WS_URL: str = "ws://localhost:8000/ws"
    API_URL: str = "http://localhost:8000"
    HEALTH_ENDPOINT: str = "/health"
    TIMEOUT: int = 5

@dataclass(frozen=True)
class DashboardConfig:
    MAX_HISTORY: int = 1000
    MAX_DEVICES: int = 20
    REFRESH_INTERVALS: List[int] = field(default_factory=lambda: [1, 2, 3, 5])
    DEFAULT_REFRESH: int = 2
    MAX_RECONNECT_ATTEMPTS: int = 10
    RECONNECT_COOLDOWN: int = 300  # 5 minutes
    MAX_BACKOFF_SECONDS: int = 120
    ANOMALY_THRESHOLD_CRITICAL: float = 30.0
    ANOMALY_THRESHOLD_HIGH: float = 50.0
    ANOMALY_THRESHOLD_MEDIUM: float = 70.0

# Modern SOC Dashboard Color Palette
COLORS = {
    "primary": "#4361ee",      # Royal Blue
    "success": "#06d6a0",       # Mint
    "warning": "#ffb703",       # Amber
    "danger": "#ef476f",        # Pink/Red
    "info": "#4cc9f0",          # Cyan
    "purple": "#7209b7",        # Purple
    "dark": "#0b132b",          # Dark Navy
    "dark_card": "#1d2b3f",     # Navy Card
    "darker": "#0a0f1e",        # Almost Black
    "text_primary": "#f8f9fa",  # Almost White
    "text_secondary": "#adb5bd", # Gray
    "border": "#2a3a52",        # Blue Gray
}

API_CONFIG = APIConfig()
DASHBOARD_CONFIG = DashboardConfig()

# =============================================================================
# WEBSOCKET MANAGER (Enterprise Edition)
# =============================================================================

class WebSocketManager:
    _instance = None
    _lock = threading.Lock()
    
    def __new__(cls):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super().__new__(cls)
                cls._instance._initialized = False
            return cls._instance
    
    def __init__(self):
        if self._initialized:
            return
        self._initialized = True
        self.message_queue = queue.Queue(maxsize=1000)
        self.connected = False
        self.reconnect_attempts = 0
        self.max_reconnect_attempts = DASHBOARD_CONFIG.MAX_RECONNECT_ATTEMPTS
        self.reconnect_delay = 3
        self.last_reconnect_time = time.time()
        self.last_successful_connection = None  # Initialize as None
        self.error_log = deque(maxlen=50)  # Store last 50 errors
        self.ws = None
        self._stop_event = threading.Event()
        self._thread = None
        # ADD THESE TWO LINES:
        self._connection_in_progress = False
        self._connection_lock = threading.Lock()
        self._start_connection()
    
    def _start_connection(self):
        with self._connection_lock:
            if self._connection_in_progress or (self._thread and self._thread.is_alive()):
                return
            self._connection_in_progress = True

        def run_websocket():
            url = API_CONFIG.WS_URL
            while not self._stop_event.is_set():
                try:
                    # Check if we've exceeded max reconnect attempts
                    if self.reconnect_attempts >= self.max_reconnect_attempts:
                        # Cool down period
                        if time.time() - self.last_reconnect_time > DASHBOARD_CONFIG.RECONNECT_COOLDOWN:
                            with self._connection_lock:
                                self.reconnect_attempts = 0
                        else:
                            time.sleep(60)
                            continue
                
                    self.ws = websocket.WebSocketApp(
                        url,
                        on_open=self._on_open,
                        on_message=self._on_message,
                        on_error=self._on_error,
                        on_close=self._on_close
                    )
                    self.ws.run_forever(ping_interval=30, ping_timeout=10)
                except Exception as e:
                    error_msg = f"WebSocket connection error: {str(e)}"
                    self.error_log.append((datetime.now(), error_msg))
                    logger.error(error_msg)
                    print(f"[ERROR] {error_msg}")
                
                if self._stop_event.is_set():
                    break
                
                with self._connection_lock:
                    self.reconnect_attempts += 1
                self.last_reconnect_time = time.time()
                
                # Exponential backoff with jitter to avoid reconnect storms.
                exp_delay = min(
                    self.reconnect_delay * (2 ** min(self.reconnect_attempts - 1, 8)),
                    DASHBOARD_CONFIG.MAX_BACKOFF_SECONDS
                )
                jitter = random.uniform(0, min(5, exp_delay * 0.2))
                delay = exp_delay + jitter
                time.sleep(delay)
            
            with self._connection_lock:
                self._connection_in_progress = False
    
        self._thread = threading.Thread(target=run_websocket, daemon=True)
        self._thread.start()
    
    def _on_open(self, ws):
        if self.connected:  # Already connected, ignore
            return
        self.connected = True
        self.reconnect_attempts = 0
        self.last_successful_connection = datetime.now()
        logger.info(f"WebSocket connected successfully at {self.last_successful_connection}")
        print(f"[OK] WebSocket connected at {self.last_successful_connection.strftime('%H:%M:%S')}")
    
    def _on_message(self, ws, message):
        try:
            data = json.loads(message)
            if data.get("type") == "connection":
                return
            if 'timestamp' not in data:
                data['timestamp'] = datetime.now().isoformat()
            self.message_queue.put(data, timeout=0.1)
        except json.JSONDecodeError as e:
            error_msg = f"Invalid JSON received: {str(e)}"
            self.error_log.append((datetime.now(), error_msg))
            logger.warning(error_msg)
        except Exception as e:
            error_msg = f"Error processing message: {str(e)}"
            self.error_log.append((datetime.now(), error_msg))
            logger.error(error_msg)
    
    def _on_error(self, ws, error):
        self.connected = False
        error_msg = f"WebSocket error: {error}"
        self.error_log.append((datetime.now(), error_msg))
        logger.error(error_msg)
        # Use safe print without emojis
        print(f"[ERROR] {error_msg}")
    
    def _on_close(self, ws, close_status_code, close_msg):
        self.connected = False
        close_info = f"close_code: {close_status_code}, message: {close_msg}"
        logger.info(f"WebSocket disconnected: {close_info}")
        # Use safe print without emojis
        print(f"[DISCONNECT] WebSocket disconnected at {datetime.now().strftime('%H:%M:%S')}")
    
    def stop(self):
        self._stop_event.set()
        with self._connection_lock:
            if self.ws:
                try:
                    self.ws.close()
                except Exception as e:
                    logger.error(f"Error closing WebSocket: {e}")
            self._connection_in_progress = False
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2)
    
    def get_messages(self, max_messages: int = 10) -> List[Dict]:
        messages = []
        try:
            for _ in range(max_messages):
                msg = self.message_queue.get_nowait()
                messages.append(msg)
        except queue.Empty:
            pass
        return messages
    
    def is_connected(self) -> bool:
        return self.connected
    
    def get_error_log(self) -> List[tuple]:
        return list(self.error_log)

# =============================================================================
# SESSION INITIALIZATION
# =============================================================================

@dataclass
class DeviceHistory:
    scores: deque = field(default_factory=lambda: deque(maxlen=DASHBOARD_CONFIG.MAX_HISTORY))
    alerts: List[datetime] = field(default_factory=list)
    last_update: Optional[datetime] = None
    minute_buckets: Dict[str, int] = field(default_factory=dict)  # Pre-computed minute buckets for heatmaps
    
    def add_score(self, score: Dict[str, Any]) -> None:
        # Safer timestamp parsing
        if isinstance(score.get('timestamp'), str):
            try:
                # Try ISO format first
                score['timestamp'] = datetime.fromisoformat(score['timestamp'].replace('Z', '+00:00'))
            except (ValueError, TypeError):
                try:
                    # Try parsing with pandas (more flexible)
                    score['timestamp'] = pd.to_datetime(score['timestamp'])
                except:
                    # Fallback to now
                    score['timestamp'] = datetime.now()
        
        # Pre-compute minute bucket for heatmaps
        if score.get('is_anomaly', False):
            minute_key = score['timestamp'].strftime('%Y-%m-%d %H:%M')
            self.minute_buckets[minute_key] = self.minute_buckets.get(minute_key, 0) + 1
        
        self.scores.append(score)
        self.last_update = datetime.now()
        if score.get('is_anomaly', False):
            self.alerts.append(datetime.now())
    
    def get_df(self) -> pd.DataFrame:
        if not self.scores:
            return pd.DataFrame()
        return pd.DataFrame(list(self.scores))

def init_session_state() -> None:
    defaults = {
        'ws_manager': WebSocketManager(),
        'device_histories': defaultdict(DeviceHistory),
        'all_history': None,  # Cache for merged data
        'selected_device': 'all',
        'auto_refresh': True,
        'refresh_interval': DASHBOARD_CONFIG.DEFAULT_REFRESH,
        'alert_count': 0,
        'last_update': datetime.now(),
        'system_start': datetime.now(),
        'paused': False,
        'chart_counter': 0,
        'show_error_log': False,
        'export_format': 'csv',
        'cleanup_registered': False,
    }
    for key, value in defaults.items():
        if key not in st.session_state:
            st.session_state[key] = value

init_session_state()

def cleanup_dashboard_resources() -> None:
    """Close long-lived resources on process exit."""
    ws_manager = st.session_state.get('ws_manager')
    if ws_manager:
        ws_manager.stop()

if not st.session_state.cleanup_registered:
    atexit.register(cleanup_dashboard_resources)
    st.session_state.cleanup_registered = True

# =============================================================================
# UTILITIES
# =============================================================================

def format_timedelta(td: timedelta) -> str:
    seconds = int(td.total_seconds())
    if seconds < 60:
        return f"{seconds}s"
    minutes = seconds // 60
    if minutes < 60:
        return f"{minutes}m {seconds % 60}s"
    hours = minutes // 60
    return f"{hours}h {minutes % 60}m"

def render_chart_safe(chart_factory, error_label: str) -> None:
    """Render a Plotly chart with a UI-safe failure boundary."""
    try:
        fig = chart_factory()
        st.plotly_chart(fig, width='stretch')  # updated from use_container_width
    except Exception as e:
        logger.error(f"{error_label}: {e}", exc_info=True)
        st.error(f"{error_label}. Check dashboard.log for details.")

def style_verdict_column(df: pd.DataFrame, verdict_column: str = 'Verdict'):
    """Apply verdict styles without deprecated Styler APIs."""
    if verdict_column not in df.columns:
        return df

    def verdict_style(verdict: str) -> str:
        return f"color: {get_verdict_color(verdict)}; font-weight: 600;"

    try:
        return df.style.map(verdict_style, subset=[verdict_column])
    except Exception:
        return df

def process_websocket_messages() -> List[Dict[str, Any]]:
    if st.session_state.paused or not st.session_state.ws_manager.is_connected():
        return []
    
    messages = st.session_state.ws_manager.get_messages()
    if not messages:
        return []
    
    for msg in messages:
        device_id = msg.get('device_id', 'unknown')
        # defaultdict handles missing keys automatically
        st.session_state.device_histories[device_id].add_score(msg)
        if msg.get('is_anomaly', False):
            st.session_state.alert_count += 1
    
    # Invalidate cache
    st.session_state.all_history = None
    st.session_state.last_update = datetime.now()
    st.session_state.chart_counter += 1
    
    return messages

def get_current_device_history() -> DeviceHistory:
    if st.session_state.selected_device == 'all':
        # Check cache first
        if st.session_state.all_history is not None:
            return st.session_state.all_history
        
        # Build merged history (optimized)
        merged = DeviceHistory()
        total_scores = 0
        for device_history in st.session_state.device_histories.values():
            score_count = len(device_history.scores)
            total_scores += score_count
            if score_count > 0:
                # More efficient than copying one by one
                merged.scores.extend(device_history.scores)
        
        # Trim if needed (deque handles maxlen automatically)
        merged.scores = deque(list(merged.scores)[-DASHBOARD_CONFIG.MAX_HISTORY:], 
                             maxlen=DASHBOARD_CONFIG.MAX_HISTORY)
        
        # Cache it
        st.session_state.all_history = merged
        return merged
    
    return st.session_state.device_histories.get(
        st.session_state.selected_device, DeviceHistory()
    )

def get_available_devices() -> List[str]:
    return ['all'] + sorted(list(st.session_state.device_histories.keys()))

def get_verdict_color(verdict: str) -> str:
    colors = {
        'NORMAL': COLORS['success'],
        'SUSPICIOUS': COLORS['warning'],
        'RISKY': '#f97316',
        'ANOMALY': COLORS['danger'],
        'UNCERTAIN': COLORS['info']
    }
    return colors.get(verdict, COLORS['text_secondary'])

def get_dynamic_threshold(device_id: str = None) -> float:
    """Get dynamic anomaly threshold based on device profile."""
    # Could be extended to use device-specific thresholds
    # For now, return default based on overall anomaly rate
    history = get_current_device_history()
    df = history.get_df()
    if df.empty:
        return DASHBOARD_CONFIG.ANOMALY_THRESHOLD_CRITICAL
    
    anomaly_rate = df['is_anomaly'].sum() / len(df) if 'is_anomaly' in df.columns else 0
    if anomaly_rate > 0.2:  # High anomaly rate - lower threshold
        return DASHBOARD_CONFIG.ANOMALY_THRESHOLD_CRITICAL * 0.8
    return DASHBOARD_CONFIG.ANOMALY_THRESHOLD_CRITICAL

def calculate_rolling_anomaly_rate(df: pd.DataFrame, minutes: int = 5, reference_time: datetime = None) -> float:
    """Calculate anomaly rate for last N minutes using data timestamps."""
    if df.empty or 'timestamp' not in df.columns:
        return 0.0
    
    # Use the latest timestamp in the data as reference, or fallback to now
    if reference_time is None:
        reference_time = df['timestamp'].max() if not df.empty else datetime.now()
    
    cutoff = reference_time - timedelta(minutes=minutes)
    recent = df[df['timestamp'] >= cutoff]
    if len(recent) == 0:
        return 0.0
    return (recent['is_anomaly'].sum() / len(recent) * 100) if 'is_anomaly' in recent.columns else 0.0

def export_device_data(format: str = 'csv') -> str:
    """Export all device data in specified format."""
    data = []
    for device_id, history in st.session_state.device_histories.items():
        df = history.get_df()
        if not df.empty:
            df_copy = df.copy()
            df_copy['device_id'] = device_id
            data.append(df_copy)
    
    if not data:
        return ""
    
    combined_df = pd.concat(data, ignore_index=True)
    
    if format == 'csv':
        return combined_df.to_csv(index=False)
    elif format == 'json':
        return combined_df.to_json(orient='records', date_format='iso')
    else:
        return combined_df.to_csv(index=False)

# =============================================================================
# CUSTOM CSS
# =============================================================================

def load_css():
    st.markdown(f"""
    <style>
        #MainMenu, footer, header {{visibility: hidden;}}
        
        ::-webkit-scrollbar {{
            width: 6px;
            height: 6px;
        }}
        ::-webkit-scrollbar-track {{
            background: {COLORS['dark']};
        }}
        ::-webkit-scrollbar-thumb {{
            background: {COLORS['primary']};
            border-radius: 3px;
        }}
        
        .stApp {{
            background: {COLORS['dark']};
        }}
        
        .metric-card {{
            background: linear-gradient(135deg, {COLORS['dark_card']} 0%, {COLORS['dark']} 100%);
            border: 1px solid {COLORS['border']};
            border-radius: 12px;
            padding: 1.2rem;
            margin: 0.5rem 0;
            box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.2);
            transition: transform 0.2s, box-shadow 0.2s;
        }}
        .metric-card:hover {{
            transform: translateY(-2px);
            box-shadow: 0 10px 15px -3px rgba(0, 0, 0, 0.3);
        }}
        
        .dashboard-header {{
            background: linear-gradient(135deg, {COLORS['primary']} 0%, {COLORS['purple']} 100%);
            padding: 1.5rem 2rem;
            border-radius: 15px;
            margin-bottom: 1.5rem;
            box-shadow: 0 10px 15px -3px rgba(0, 0, 0, 0.3);
        }}
        
        .status-badge {{
            display: inline-block;
            padding: 0.25rem 0.75rem;
            border-radius: 20px;
            font-size: 0.85rem;
            font-weight: 600;
            text-transform: uppercase;
        }}
        
        .verdict-normal {{
            background: {COLORS['success']}20;
            color: {COLORS['success']};
            border: 1px solid {COLORS['success']}40;
        }}
        .verdict-suspicious {{
            background: {COLORS['warning']}20;
            color: {COLORS['warning']};
            border: 1px solid {COLORS['warning']}40;
        }}
        .verdict-risky {{
            background: #f9731620;
            color: #f97316;
            border: 1px solid #f9731640;
        }}
        .verdict-anomaly {{
            background: {COLORS['danger']}20;
            color: {COLORS['danger']};
            border: 1px solid {COLORS['danger']}40;
        }}
        
        @keyframes glow {{
            0% {{ box-shadow: 0 0 5px {COLORS['danger']}; }}
            50% {{ box-shadow: 0 0 20px {COLORS['danger']}; }}
            100% {{ box-shadow: 0 0 5px {COLORS['danger']}; }}
        }}
        .anomaly-glow {{
            animation: glow 2s infinite;
        }}
        
        .error-log {{
            background: {COLORS['dark_card']};
            border-left: 4px solid {COLORS['danger']};
            padding: 1rem;
            margin: 0.5rem 0;
            border-radius: 4px;
            font-family: monospace;
            font-size: 0.9rem;
        }}
    </style>
    """, unsafe_allow_html=True)

# =============================================================================
# UI COMPONENTS
# =============================================================================

def render_metric_card(title: str, value: str, icon: str, color: str = None):
    color = color or COLORS['text_primary']
    st.markdown(f"""
    <div class="metric-card">
        <div style="display: flex; align-items: center; margin-bottom: 0.5rem;">
            <span style="font-size: 1.5rem; margin-right: 0.5rem;">{icon}</span>
            <span style="color: {COLORS['text_secondary']};">{title}</span>
        </div>
        <div style="color: {color}; font-size: 2rem; font-weight: 700;">{value}</div>
    </div>
    """, unsafe_allow_html=True)

def render_verdict_badge(verdict: str) -> str:
    class_map = {
        'NORMAL': 'verdict-normal',
        'SUSPICIOUS': 'verdict-suspicious',
        'RISKY': 'verdict-risky',
        'ANOMALY': 'verdict-anomaly'
    }
    css_class = class_map.get(verdict, 'verdict-normal')
    return f'<span class="status-badge {css_class}">{verdict}</span>'

def render_error_log():
    """Render WebSocket error log in expander."""
    with st.expander("🔍 WebSocket Error Log", expanded=False):
        errors = st.session_state.ws_manager.get_error_log()
        if errors:
            for timestamp, error in errors[-10:]:  # Show last 10 errors
                st.markdown(f"""
                <div class="error-log">
                    <small style="color: {COLORS['text_secondary']};">{timestamp.strftime('%H:%M:%S')}</small><br>
                    <span style="color: {COLORS['danger']};">{error}</span>
                </div>
                """, unsafe_allow_html=True)
        else:
            st.info("No errors logged")

# =============================================================================
# CHART FUNCTIONS
# =============================================================================

def hex_to_rgba(hex_color: str, alpha: float) -> str:
    """Convert hex color to rgba string."""
    h = hex_color.lstrip('#')
    r = int(h[0:2], 16)
    g = int(h[2:4], 16)
    b = int(h[4:6], 16)
    return f'rgba({r},{g},{b},{alpha})'

def create_gauge(value: float, title: str, threshold: float = None) -> go.Figure:
    if threshold is None:
        threshold = get_dynamic_threshold()
    
    fig = go.Figure(go.Indicator(
        mode="gauge+number",
        value=value,
        domain={'x': [0, 1], 'y': [0, 1]},
        number={'font': {'color': COLORS['text_primary'], 'size': 36}},
        gauge={
            'axis': {'range': [0, 100], 'tickcolor': COLORS['border'],
                    'tickfont': {'color': COLORS['text_secondary']}},
            'bar': {'color': COLORS['primary'], 'thickness': 0.75},
            'bgcolor': COLORS['dark_card'],
            'borderwidth': 0,
            'steps': [
                {'range': [0, threshold], 'color': hex_to_rgba(COLORS['danger'], 0.3)},
                {'range': [threshold, DASHBOARD_CONFIG.ANOMALY_THRESHOLD_HIGH], 
                 'color': hex_to_rgba('#f97316', 0.3)},
                {'range': [DASHBOARD_CONFIG.ANOMALY_THRESHOLD_HIGH, 
                          DASHBOARD_CONFIG.ANOMALY_THRESHOLD_MEDIUM], 
                 'color': hex_to_rgba(COLORS['warning'], 0.3)},
                {'range': [DASHBOARD_CONFIG.ANOMALY_THRESHOLD_MEDIUM, 100], 
                 'color': hex_to_rgba(COLORS['success'], 0.3)},
            ],
            'threshold': {
                'line': {'color': COLORS['danger'], 'width': 4},
                'thickness': 0.75,
                'value': threshold
            }
        }
    ))
    fig.update_layout(
        paper_bgcolor='rgba(0,0,0,0)',
        plot_bgcolor='rgba(0,0,0,0)',
        height=200,
        margin=dict(l=20, r=20, t=40, b=20),
        font={'color': COLORS['text_primary']}
    )
    return fig

def create_timeline(df: pd.DataFrame) -> go.Figure:
    fig = go.Figure()
    
    # Work on a copy to avoid modifying original
    df_copy = df.copy()
    
    # Create rgba fill color
    r = int(COLORS['primary'][1:3], 16)
    g = int(COLORS['primary'][3:5], 16)
    b = int(COLORS['primary'][5:7], 16)
    fillcolor = f'rgba({r}, {g}, {b}, 0.2)'
    
    # Trust score line
    fig.add_trace(go.Scatter(
        x=df_copy['timestamp'],
        y=df_copy['trust_score'],
        mode='lines',
        name='Trust Score',
        line=dict(color=COLORS['primary'], width=3),
        fill='tozeroy',
        fillcolor=fillcolor
    ))
    
    # Anomaly markers
    if 'is_anomaly' in df_copy.columns:
        anomalies = df_copy[df_copy['is_anomaly']]
        if not anomalies.empty:
            fig.add_trace(go.Scatter(
                x=anomalies['timestamp'],
                y=anomalies['trust_score'],
                mode='markers',
                name='Anomalies',
                marker=dict(color=COLORS['danger'], size=10, symbol='x'),
            ))
    
    fig.update_layout(
        title=dict(text="Trust Score Timeline", font=dict(color=COLORS['text_primary'], size=18)),
        paper_bgcolor='rgba(0,0,0,0)',
        plot_bgcolor='rgba(0,0,0,0)',
        height=300,
        margin=dict(l=40, r=40, t=50, b=40),
        hovermode='x unified',
        legend=dict(font=dict(color=COLORS['text_primary'])),
        xaxis=dict(
            title=dict(text="Time", font=dict(color=COLORS['text_secondary'])),
            gridcolor=COLORS['border'],
            tickfont=dict(color=COLORS['text_secondary'])
        ),
        yaxis=dict(
            title=dict(text="Trust Score", font=dict(color=COLORS['text_secondary'])),
            gridcolor=COLORS['border'],
            tickfont=dict(color=COLORS['text_secondary']),
            range=[0, 100]
        )
    )
    return fig

def create_heatmap(df: pd.DataFrame) -> go.Figure:
    if df.empty or 'timestamp' not in df.columns:
        return go.Figure()
    
    # Work on a copy to avoid modifying original
    df_copy = df.copy()
    df_copy['minute'] = df_copy['timestamp'].dt.floor('min')
    
    heat_data = df_copy.groupby('minute').agg({
        'is_anomaly': 'sum',
        'trust_score': 'mean'
    }).reset_index()
    
    fig = go.Figure(data=go.Heatmap(
        z=[heat_data['is_anomaly'].tolist()],
        x=heat_data['minute'].tolist(),
        y=['Anomalies'],
        colorscale='Reds',
        showscale=True,
        colorbar=dict(
            title=dict(text="Count", font=dict(color=COLORS['text_secondary'])),
            tickfont=dict(color=COLORS['text_secondary'])
        )
    ))
    
    fig.update_layout(
        title=dict(text="Anomaly Frequency", font=dict(color=COLORS['text_primary'], size=16)),
        paper_bgcolor='rgba(0,0,0,0)',
        plot_bgcolor='rgba(0,0,0,0)',
        height=120,
        margin=dict(l=40, r=40, t=40, b=20),
        xaxis=dict(tickfont=dict(color=COLORS['text_secondary']), showgrid=False),
        yaxis=dict(tickfont=dict(color=COLORS['text_secondary']))
    )
    return fig

# =============================================================================
# MAIN DASHBOARD
# =============================================================================

def main():
    st.set_page_config(
        page_title="IoT Sentinel - SOC Platform",
        page_icon="🛡️",
        layout="wide",
        initial_sidebar_state="expanded"
    )
    
    load_css()
    
    # Auto refresh
    if st.session_state.auto_refresh and not st.session_state.paused:
        st_autorefresh(
            interval=st.session_state.refresh_interval * 1000,
            key=f"refresh_{st.session_state.refresh_interval}",
            limit=100000
        )
    
    # Process messages
    process_websocket_messages()
    
    # =========================================================================
    # SIDEBAR
    # =========================================================================
    with st.sidebar:
        st.markdown(f"""
        <div style="text-align: center; margin-bottom: 2rem;">
            <h1 style="color: white; margin: 0;">🎮</h1>
            <h3 style="color: {COLORS['text_primary']};">Control Panel</h3>
        </div>
        """, unsafe_allow_html=True)
        
        # Device Selection
        st.markdown("### 📱 Device View")
        devices = get_available_devices()
        if devices:
            device_labels = ["🌐 All Devices" if x == 'all' else f"🖥️ {x}" for x in devices]
            selected_idx = st.selectbox(
                "Select",
                options=range(len(devices)),
                format_func=lambda x: device_labels[x],
                key="device_selector"
            )
            st.session_state.selected_device = devices[selected_idx]
        
        st.markdown("---")
        
        # Controls
        st.markdown("### 🎮 Controls")
        col1, col2 = st.columns(2)
        with col1:
            st.session_state.auto_refresh = st.toggle("🔄 Auto", value=True)
        with col2:
            st.session_state.paused = st.toggle("⏸️ Pause", value=False)
        
        if st.session_state.auto_refresh:
            st.session_state.refresh_interval = st.slider("Interval (s)", 1, 5, 2)
        
        st.markdown("---")
        
        # Quick Actions
        st.markdown("### ⚡ Actions")
        
        # Test alert with different verdicts
        verdict_options = ['NORMAL', 'SUSPICIOUS', 'RISKY', 'ANOMALY']
        selected_verdict = st.selectbox("Test Verdict Type", verdict_options, index=3)
        
        if st.button("🧪 Generate Test Alert", use_container_width=True):
            device_id = f'test_{random.randint(1,3)}'
            
            # Set score based on verdict
            if selected_verdict == 'NORMAL':
                trust_score = random.uniform(75, 95)
                risk_factors = []
            elif selected_verdict == 'SUSPICIOUS':
                trust_score = random.uniform(55, 69)
                risk_factors = ['Unusual pattern detected']
            elif selected_verdict == 'RISKY':
                trust_score = random.uniform(35, 49)
                risk_factors = ['Multiple suspicious patterns']
            else:  # ANOMALY
                trust_score = random.uniform(15, 29)
                risk_factors = ['Critical anomaly detected', 'Immediate attention required']
            
            mock_data = {
                'device_id': device_id,
                'trust_score': trust_score,
                'ml_score': random.uniform(20, 95),
                'rule_score': random.uniform(0, 90),
                'is_anomaly': selected_verdict == 'ANOMALY',
                'verdict': selected_verdict,
                'confidence': random.uniform(70, 98),
                'risk_factors': risk_factors,
                'timestamp': datetime.now().isoformat()
            }
            st.session_state.device_histories[device_id].add_score(mock_data)
            st.session_state.all_history = None  # Invalidate cache
            st.success(f"✅ {selected_verdict} alert generated for {device_id}")
            st.rerun()
        
        # Export data
        export_format = st.selectbox("Export Format", ['csv', 'json'])
        if st.button("📥 Export Data", use_container_width=True):
            data = export_device_data(export_format)
            if data:
                st.download_button(
                    label=f"Download {export_format.upper()}",
                    data=data,
                    file_name=f"iot_data_{datetime.now().strftime('%Y%m%d_%H%M%S')}.{export_format}",
                    mime=f"text/{export_format}" if export_format == 'csv' else "application/json"
                )
            else:
                st.warning("No data to export")
        
        if st.button("🗑️ Clear All Data", use_container_width=True):
            st.session_state.device_histories.clear()
            st.session_state.all_history = None
            st.session_state.alert_count = 0
            st.success("✅ Data cleared")
            st.rerun()
        
        st.markdown("---")
        
        # System Status
        st.markdown("### 📊 System Status")
        ws_manager = st.session_state.ws_manager
        ws_status = "🟢 Connected" if ws_manager.is_connected() else "🔴 Disconnected"
        reconnect_info = ""
        if not ws_manager.is_connected():
            reconnect_info = f" (attempt {ws_manager.reconnect_attempts}/{ws_manager.max_reconnect_attempts})"
        
        st.markdown(f"**WebSocket:** {ws_status}{reconnect_info}")
        
        if ws_manager.last_successful_connection:
            last_conn = ws_manager.last_successful_connection.strftime('%H:%M:%S')
            st.markdown(f"**Last Connected:** {last_conn}")
        
        st.markdown(f"**Active Devices:** {len(st.session_state.device_histories)}")
        total = sum(len(h.scores) for h in st.session_state.device_histories.values())
        st.markdown(f"**Total Events:** {total}")
        uptime = datetime.now() - st.session_state.system_start
        st.markdown(f"**Uptime:** {format_timedelta(uptime)}")
        
        # Rolling anomaly rate
        if total > 0:
            history = get_current_device_history()
            df = history.get_df()
            rolling_rate = calculate_rolling_anomaly_rate(df, reference_time=df['timestamp'].max() if not df.empty else None)
            rate_color = COLORS['success'] if rolling_rate < 10 else COLORS['warning'] if rolling_rate < 20 else COLORS['danger']
            st.markdown(f"**5-min Anomaly Rate:** <span style='color:{rate_color}'>{rolling_rate:.1f}%</span>", 
                       unsafe_allow_html=True)
        
        # Error log toggle
        st.session_state.show_error_log = st.checkbox("🔍 Show Error Log", value=False)
        
        if st.session_state.show_error_log:
            render_error_log()
    
    # =========================================================================
    # MAIN CONTENT
    # =========================================================================
    
    # Header
    st.markdown(f"""
    <div class="dashboard-header">
        <div style="display: flex; justify-content: space-between; align-items: center;">
            <div>
                <h1 style="color: white; margin: 0; font-size: 2rem;">🛡️ IoT Sentinel</h1>
                <p style="color: rgba(255,255,255,0.8); margin: 0;">Enterprise SOC Platform</p>
            </div>
            <div style="text-align: right;">
                <div style="color: white; font-size: 1.2rem;">{datetime.now().strftime('%H:%M:%S')}</div>
                <div style="color: rgba(255,255,255,0.6);">Live Monitoring</div>
            </div>
        </div>
    </div>
    """, unsafe_allow_html=True)
    
    # Get data
    history = get_current_device_history()
    df = history.get_df()
    
    if df.empty:
        col1, col2, col3 = st.columns([1, 2, 1])
        with col2:
            st.markdown(f"""
            <div style="text-align: center; padding: 4rem 2rem;">
                <div style="font-size: 5rem; margin-bottom: 1rem;">📡</div>
                <h2 style="color: {COLORS['text_primary']};">Waiting for Data</h2>
                <p style="color: {COLORS['text_secondary']};">Start the traffic simulator or connect to WebSocket</p>
            </div>
            """, unsafe_allow_html=True)
        return
    
    # Key Metrics Row
    st.markdown("### 📊 Key Metrics")
    latest = df.iloc[-1].to_dict()
    
    cols = st.columns(4)
    with cols[0]:
        trust_color = COLORS['success'] if latest['trust_score'] >= 70 else \
                     COLORS['warning'] if latest['trust_score'] >= 50 else \
                     '#f97316' if latest['trust_score'] >= 30 else COLORS['danger']
        render_metric_card("Trust Score", f"{latest['trust_score']:.1f}", "🎯", trust_color)
    
    with cols[1]:
        verdict = latest.get('verdict', 'N/A')
        st.markdown(f"""
        <div class="metric-card">
            <div style="display: flex; align-items: center; margin-bottom: 0.5rem;">
                <span style="font-size: 1.5rem; margin-right: 0.5rem;">⚖️</span>
                <span style="color: {COLORS['text_secondary']};">Verdict</span>
            </div>
            <div>{render_verdict_badge(verdict)}</div>
        </div>
        """, unsafe_allow_html=True)
    
    with cols[2]:
        render_metric_card("Confidence", f"{latest.get('confidence', 0):.1f}%", "✅")
    
    with cols[3]:
        anomaly_rate = (df['is_anomaly'].sum() / len(df) * 100) if 'is_anomaly' in df.columns else 0
        rate_color = COLORS['success'] if anomaly_rate < 10 else \
                    COLORS['warning'] if anomaly_rate < 20 else COLORS['danger']
        render_metric_card("Anomaly Rate", f"{anomaly_rate:.1f}%", "⚠️", rate_color)
    
    st.markdown("---")
    
    # Charts Row
    col1, col2 = st.columns([2, 1])
    
    with col1:
        render_chart_safe(lambda: create_timeline(df.tail(100)), "Failed to render timeline chart")
    
    with col2:
        dynamic_threshold = get_dynamic_threshold()
        render_chart_safe(
            lambda: create_gauge(latest['trust_score'], "Current Trust", threshold=dynamic_threshold),
            "Failed to render trust gauge"
        )
        
        st.markdown(f"""
        <div style="background: {COLORS['dark_card']}; padding: 1rem; border-radius: 12px; margin-top: 1rem;">
            <div style="display: flex; justify-content: space-between; margin-bottom: 0.5rem;">
                <span style="color: {COLORS['text_secondary']};">Risk Factors:</span>
                <span style="color: {COLORS['warning']}; font-weight: 600;">{len(latest.get('risk_factors', []))}</span>
            </div>
            <div style="display: flex; justify-content: space-between;">
                <span style="color: {COLORS['text_secondary']};">Data Points:</span>
                <span style="color: {COLORS['text_primary']}; font-weight: 600;">{len(df)}</span>
            </div>
            <div style="display: flex; justify-content: space-between; margin-top: 0.5rem;">
                <span style="color: {COLORS['text_secondary']};">Dynamic Threshold:</span>
                <span style="color: {COLORS['info']}; font-weight: 600;">{dynamic_threshold:.1f}</span>
            </div>
        </div>
        """, unsafe_allow_html=True)
    
    st.markdown("---")
    
    # Device Health Table
    st.markdown("### 📱 Device Health")
    
    device_stats = []
    for device_id, device_history in st.session_state.device_histories.items():
        device_df = device_history.get_df()
        if not device_df.empty:
            latest_dev = device_df.iloc[-1].to_dict()
            
            device_stats.append({
                'Device': device_id[:15] + '...' if len(device_id) > 15 else device_id,
                'Trust Score': f"{latest_dev.get('trust_score', 0):.1f}",
                'Verdict': latest_dev.get('verdict', 'N/A'),
                'Confidence': f"{latest_dev.get('confidence', 0):.1f}%",
                'Events': len(device_df),
                'Anomalies': device_df['is_anomaly'].sum() if 'is_anomaly' in device_df.columns else 0
            })
    
    if device_stats:
        stats_df = pd.DataFrame(device_stats)
        
        display_df = stats_df[['Device', 'Trust Score', 'Verdict', 'Confidence', 'Events', 'Anomalies']].copy()
        styled_stats = style_verdict_column(display_df, verdict_column='Verdict')
        
        st.dataframe(styled_stats, width='stretch', height=250)
    
    st.markdown("---")
    
    # Recent Events
    st.markdown("### 📋 Recent Events")
    
    event_df = df.tail(20).copy()
    if not event_df.empty:
        display_data = []
        for _, row in event_df.iterrows():
            display_data.append({
                'Time': row['timestamp'].strftime('%H:%M:%S'),
                'Device': row.get('device_id', 'unknown')[:10],
                'Score': f"{row.get('trust_score', 0):.1f}",
                'Verdict': row.get('verdict', 'N/A'),
                'Risk Factors': ', '.join(row.get('risk_factors', []))[:40] if row.get('risk_factors') else 'None',
                'Confidence': f"{row.get('confidence', 0):.1f}%"
            })
        
        events_df = pd.DataFrame(display_data)
        styled_events = style_verdict_column(events_df, verdict_column='Verdict')
        
        st.dataframe(styled_events, width='stretch', height=350)
    
    # Heatmap
    render_chart_safe(lambda: create_heatmap(df.tail(300)), "Failed to render anomaly heatmap")

if __name__ == "__main__":
    main()
