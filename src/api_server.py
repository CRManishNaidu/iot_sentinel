"""
IoT Sentinel API Server
FastAPI server for IoT device trust scoring integrated with engine module.
"""
import os
import logging
import time
import uuid
import threading
from contextlib import asynccontextmanager
from datetime import datetime
from typing import List, Optional, Dict, Any
from collections import deque

from fastapi import FastAPI, HTTPException, Request, status, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, PlainTextResponse, Response
from pydantic import BaseModel, Field, validator
import asyncio
import uvicorn

# Rate limiting with fallback
try:
    from slowapi import Limiter, _rate_limit_exceeded_handler
    from slowapi.util import get_remote_address
    from slowapi.errors import RateLimitExceeded
    SLOWAPI_AVAILABLE = True
except ImportError:
    SLOWAPI_AVAILABLE = False
    # Create dummy classes for fallback
    class RateLimitExceeded(Exception):
        pass

# Import from engine
from src.engine import load_engine

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Constants
APP_VERSION = "1.0.0"
APP_NAME = "IoT Sentinel API"

# Metrics tracking
class Metrics:
    """Thread-safe in-memory metrics collector."""
    def __init__(self, window_size: int = 1000):
        self.request_count = 0
        self.anomaly_count = 0
        self.latencies = deque(maxlen=window_size)
        self.last_latency = 0
        self._lock = threading.Lock()
        
    def record_request(self, latency_ms: float, is_anomaly: bool = False):
        with self._lock:
            self.request_count += 1
            self.latencies.append(latency_ms)
            self.last_latency = latency_ms
            if is_anomaly:
                self.anomaly_count += 1
    
    def get_avg_latency(self) -> float:
        with self._lock:
            if not self.latencies:
                return 0
            return sum(self.latencies) / len(self.latencies)
    
    def get_stats(self) -> Dict[str, Any]:
        with self._lock:
            avg_latency = (sum(self.latencies) / len(self.latencies)) if self.latencies else 0
            return {
                "request_count": self.request_count,
                "anomaly_count": self.anomaly_count,
                "avg_latency_ms": round(avg_latency, 2),
                "last_latency_ms": self.last_latency
            }

metrics = Metrics()

class HealthResponse(BaseModel):
    """Health check response model."""
    status: str = Field(..., example="healthy")
    model_loaded: bool = Field(..., example=True)
    timestamp: datetime = Field(default_factory=datetime.utcnow)

class ScoreRequest(BaseModel):
    """Request model for network telemetry scoring."""
    duration: float = Field(..., description="Connection duration in seconds", example=5.2, ge=0)
    orig_bytes: float = Field(..., description="Bytes sent from origin", example=1500, ge=0)
    resp_bytes: float = Field(..., description="Bytes sent from responder", example=2000, ge=0)
    orig_pkts: int = Field(..., description="Packets sent from origin", example=25, ge=0)
    resp_pkts: int = Field(..., description="Packets sent from responder", example=30, ge=0)
    proto: str = Field(..., description="Protocol (TCP/UDP/ICMP)", example="TCP")
    conn_state: str = Field(..., description="Connection state", example="SF")
    device_id: Optional[str] = Field("device_1", description="Device identifier")

    @validator("proto")
    def validate_proto(cls, v: str) -> str:
        """Validate protocol is supported."""
        v = v.upper()
        if v not in ["TCP", "UDP", "ICMP"]:
            raise ValueError(f"Protocol must be TCP, UDP, or ICMP, got {v}")
        return v

    @validator("conn_state")
    def validate_conn_state(cls, v: str) -> str:
        """Validate connection state."""
        valid_states = ["SF", "S0", "REJ", "RST", "SH", "SHR", "OTH"]
        if v not in valid_states:
            raise ValueError(f"Connection state must be one of {valid_states}, got {v}")
        return v

class ScoreResponse(BaseModel):
    """Response model for telemetry scoring."""
    trust_score: float = Field(..., ge=0, le=100, example=84.5)
    ml_score: float = Field(..., ge=0, le=100, example=88.2)
    rule_score: float = Field(..., ge=0, le=100, example=75.0)
    entropy_score: Optional[float] = Field(None, ge=0, le=100)
    is_anomaly: bool = Field(..., example=False)
    verdict: str = Field(..., example="NORMAL")
    confidence: float = Field(..., ge=0, le=100, example=92.3)
    risk_factors: List[str] = Field(default_factory=list)
    top_features: List[str] = Field(default_factory=list)
    processing_time_ms: float = Field(..., example=15.6)

class ErrorResponse(BaseModel):
    """Standard error response model."""
    error: str
    detail: Optional[str] = None
    timestamp: datetime = Field(default_factory=datetime.utcnow)

# WebSocket connection manager
class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []
        self._lock = asyncio.Lock()

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        async with self._lock:
            self.active_connections.append(websocket)

    async def disconnect(self, websocket: WebSocket):
        async with self._lock:
            if websocket in self.active_connections:
                self.active_connections.remove(websocket)

    async def broadcast(self, message: Dict[str, Any]):
        """Broadcast message to all connected clients."""
        if not self.active_connections:
            logger.debug("No active WebSocket connections to broadcast to")
            return
            
        disconnected = []
        async with self._lock:
            logger.debug(f"Broadcasting to {len(self.active_connections)} clients")
            for i, connection in enumerate(self.active_connections):
                try:
                    await connection.send_json(message)
                except Exception as e:
                    logger.warning(f"Failed to send to client {i+1}: {e}")
                    disconnected.append(connection)
            
            # Clean up disconnected clients
            for conn in disconnected:
                if conn in self.active_connections:
                    self.active_connections.remove(conn)
                    logger.info("Removed disconnected WebSocket client")

    async def close_all(self):
        """Close active websocket connections during shutdown."""
        async with self._lock:
            connections = list(self.active_connections)
            self.active_connections.clear()
        for connection in connections:
            try:
                await connection.close(code=1001, reason="Server shutdown")
            except Exception:
                pass

manager = ConnectionManager()

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifespan context manager for startup/shutdown events."""
    # Startup
    logger.info(f"Starting {APP_NAME} v{APP_VERSION}")
    app.state.engine = None
    app.state.model_loaded = False
    
    try:
        logger.info("Loading engine...")
        engine = load_engine()
        app.state.engine = engine
        
        if engine and hasattr(engine, 'model') and hasattr(engine, 'scaler'):
            app.state.model_loaded = (engine.model is not None and engine.scaler is not None)
        
        if app.state.model_loaded:
            logger.info("Engine loaded successfully with model and scaler")
        else:
            logger.warning("Engine loaded but model/scaler not available - running in fallback mode")
            
    except Exception as e:
        logger.error(f"Failed to load engine: {str(e)}", exc_info=True)
        app.state.model_loaded = False
    
    yield
    
    # Shutdown
    await manager.close_all()
    logger.info(f"Shutting down {APP_NAME}")

# Initialize FastAPI app
app = FastAPI(
    title=APP_NAME,
    description="IoT Device Trust Scoring API - Anomaly detection for IoT devices",
    version=APP_VERSION,
    lifespan=lifespan,
    docs_url="/api/docs",
    redoc_url="/api/redoc"
)

# Ensure state fields exist
app.state.engine = None
app.state.model_loaded = False

# Configure rate limiting if available
if SLOWAPI_AVAILABLE:
    limiter = Limiter(key_func=get_remote_address)
    app.state.limiter = limiter
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
else:
    logger.warning("slowapi not installed - rate limiting disabled")

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.state.start_time = datetime.utcnow()

@app.middleware("http")
async def add_timing(request: Request, call_next):
    """Add request processing time to response headers."""
    start = time.time()
    response = await call_next(request)
    duration = (time.time() - start) * 1000
    response.headers["X-Process-Time-ms"] = str(round(duration, 2))
    return response

@app.middleware("http")
async def add_request_id(request: Request, call_next):
    """Add request ID to each request."""
    request_id = str(uuid.uuid4())
    request.state.request_id = request_id
    response = await call_next(request)
    response.headers["X-Request-ID"] = request_id
    return response

@app.middleware("http")
async def validate_score_request(request: Request, call_next):
    """Validate basic request constraints for /score endpoint."""
    if request.url.path == "/score" and request.method.upper() == "POST":
        content_type = request.headers.get("content-type", "").lower()
        if "application/json" not in content_type:
            return JSONResponse(
                status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
                content=ErrorResponse(
                    error="Unsupported media type",
                    detail="Use Content-Type: application/json for /score requests"
                ).model_dump(mode="json")
            )
        content_length = request.headers.get("content-length")
        if content_length is not None:
            try:
                if int(content_length) > 1_000_000:
                    return JSONResponse(
                        status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                        content=ErrorResponse(
                            error="Payload too large",
                            detail="Request body must be <= 1MB"
                        ).model_dump(mode="json")
                    )
            except ValueError:
                return JSONResponse(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    content=ErrorResponse(error="Invalid Content-Length header").model_dump(mode="json")
                )
    return await call_next(request)

@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException) -> JSONResponse:
    """Custom HTTP exception handler."""
    return JSONResponse(
        status_code=exc.status_code,
        content=ErrorResponse(
            error=exc.detail,
            detail=str(exc) if app.debug else None
        ).model_dump(mode="json")
    )

@app.exception_handler(Exception)
async def generic_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """Generic exception handler."""
    request_id = getattr(request.state, "request_id", "unknown")
    logger.error(f"Unexpected error: {str(exc)}", exc_info=True, extra={"request_id": request_id})
    
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content=ErrorResponse(
            error="Internal server error",
            detail=str(exc) if app.debug else None
        ).model_dump(mode="json")
    )

@app.get("/", tags=["Root"])
async def root() -> Dict[str, Any]:
    """Root endpoint with API information."""
    return {
        "name": APP_NAME,
        "version": APP_VERSION,
        "status": "operational",
        "model_loaded": app.state.model_loaded,
        "endpoints": {
            "health": "/health",
            "score": "/score",
            "docs": "/api/docs",
            "websocket": "/ws"
        }
    }

@app.get("/favicon.ico", include_in_schema=False)
async def favicon() -> Response:
    """Avoid browser 404s."""
    return Response(status_code=status.HTTP_204_NO_CONTENT)

@app.get("/health", response_model=HealthResponse, tags=["Monitoring"])
async def health_check() -> HealthResponse:
    """Enhanced health check endpoint."""
    return HealthResponse(
        status="healthy" if app.state.model_loaded else "degraded",
        model_loaded=app.state.model_loaded,
        timestamp=datetime.utcnow()
    )

@app.post("/score", response_model=ScoreResponse, status_code=status.HTTP_200_OK, tags=["Inference"])
async def score(telemetry: ScoreRequest, request: Request = None) -> ScoreResponse:
    """
    Score network telemetry and return trust metrics.
    """
    request_id = getattr(request.state, "request_id", "unknown")
    start_time = time.time()
    telemetry_dict = telemetry.model_dump()

    if not app.state.model_loaded or app.state.engine is None:
        logger.warning("Engine unavailable - using fallback", extra={"request_id": request_id})
        latency_ms = (time.time() - start_time) * 1000
        metrics.record_request(latency_ms, is_anomaly=False)
        return ScoreResponse(
            trust_score=50.0,
            ml_score=50.0,
            rule_score=0.0,
            entropy_score=50.0,
            is_anomaly=False,
            verdict="UNCERTAIN",
            confidence=45.0,
            risk_factors=["Fallback: engine unavailable"],
            top_features=[],
            processing_time_ms=latency_ms
        )

    try:
        result = app.state.engine.score_telemetry(telemetry_dict)
        if not isinstance(result, dict):
            raise ValueError("Engine returned invalid response type")

        latency_ms = (time.time() - start_time) * 1000
        verdict = str(result.get("verdict", "UNCERTAIN")).upper()
        is_anomaly = verdict in {"ANOMALY", "RISKY"}
        metrics.record_request(latency_ms, is_anomaly)

        response_payload = ScoreResponse(
            trust_score=float(result.get("trust_score", 50.0)),
            ml_score=float(result.get("ml_score", 50.0)),
            rule_score=float(result.get("rule_score", 0.0)),
            entropy_score=float(result.get("entropy_score", 50.0)),
            is_anomaly=is_anomaly,
            verdict=verdict,
            confidence=float(result.get("confidence", 50.0)),
            risk_factors=list(result.get("risk_factors", [])),
            top_features=list(result.get("top_features", [])),
            processing_time_ms=latency_ms
        )

        try:
            ws_data = {
                "device_id": telemetry.device_id,
                "trust_score": response_payload.trust_score,
                "ml_score": response_payload.ml_score,
                "rule_score": response_payload.rule_score,
                "entropy_score": response_payload.entropy_score,
                "is_anomaly": response_payload.is_anomaly,
                "verdict": response_payload.verdict,
                "confidence": response_payload.confidence,
                "risk_factors": response_payload.risk_factors,
                "timestamp": datetime.utcnow().isoformat()
            }
            await manager.broadcast(ws_data)
        except Exception as e:
            logger.warning("WebSocket broadcast error", extra={"request_id": request_id, "error": str(e)})

        return response_payload
    except ValueError as e:
        logger.warning("Validation error", extra={"request_id": request_id, "error": str(e)})
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(e)
        )
    except Exception as e:
        logger.error("Scoring failed", extra={"request_id": request_id, "error": str(e)}, exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Scoring failed"
        )

@app.get("/metrics", response_class=PlainTextResponse, tags=["Monitoring"])
async def get_metrics() -> str:
    """Prometheus-compatible metrics endpoint."""
    stats = metrics.get_stats()
    uptime_seconds = (datetime.utcnow() - app.state.start_time).total_seconds()
    
    prometheus_metrics = f"""# HELP iot_sentinel_request_total Total number of requests handled
# TYPE iot_sentinel_request_total counter
iot_sentinel_request_total {stats['request_count']}

# HELP iot_sentinel_anomaly_total Total number of anomalies detected
# TYPE iot_sentinel_anomaly_total counter
iot_sentinel_anomaly_total {stats['anomaly_count']}

# HELP iot_sentinel_latency_avg Average request latency in milliseconds
# TYPE iot_sentinel_latency_avg gauge
iot_sentinel_latency_avg {stats['avg_latency_ms']}

# HELP iot_sentinel_model_loaded Whether the ML model is loaded
# TYPE iot_sentinel_model_loaded gauge
iot_sentinel_model_loaded {1 if app.state.model_loaded else 0}

# HELP iot_sentinel_uptime_seconds Service uptime in seconds
# TYPE iot_sentinel_uptime_seconds gauge
iot_sentinel_uptime_seconds {uptime_seconds}
"""
    
    return prometheus_metrics

@app.get("/metrics/json", tags=["Monitoring"])
async def get_metrics_json() -> Dict[str, Any]:
    """JSON metrics endpoint."""
    stats = metrics.get_stats()
    uptime_seconds = (datetime.utcnow() - app.state.start_time).total_seconds()
    
    return {
        "app": APP_NAME,
        "version": APP_VERSION,
        "timestamp": datetime.utcnow().isoformat(),
        "uptime_seconds": round(uptime_seconds, 2),
        "metrics": {
            "request_count": stats["request_count"],
            "anomaly_count": stats["anomaly_count"],
            "avg_latency_ms": stats["avg_latency_ms"],
            "model_loaded": app.state.model_loaded
        }
    }

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    """WebSocket endpoint for real-time updates."""
    await manager.connect(websocket)
    try:
        # Send initial connection confirmation
        await websocket.send_json({"type": "connection", "status": "established"})
        
        # Keep connection alive
        while True:
            try:
                # Wait for any client messages (ping/pong)
                data = await websocket.receive_text()
                # Echo back for ping
                if data == "ping":
                    await websocket.send_text("pong")
            except WebSocketDisconnect:
                break
            except Exception as e:
                logger.error(f"WebSocket error: {e}")
                break
    finally:
        await manager.disconnect(websocket)

if __name__ == "__main__":
    """Run the API server."""
    port = int(os.getenv("PORT", "8000"))
    host = os.getenv("HOST", "0.0.0.0")
    reload_enabled = os.getenv("RELOAD", "true").lower() == "true"
    
    uvicorn.run(
        "src.api_server:app",
        host=host,
        port=port,
        reload=reload_enabled,
        log_level="info",
        access_log=False
    )
