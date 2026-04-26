import asyncio
import logging
import os
from contextlib import asynccontextmanager
from datetime import datetime, timezone

import uvicorn
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware

from wazuh_client import fetch_alerts, test_connection
from chatbot import router as chatbot_router

load_dotenv()


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s – %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("main")


_state: dict = {
    "last_poll_time": None,
    "last_alert_count": 0,
    "last_anomaly_count": 0,
    "cached_results": None,
    "poll_running": False,
}

POLL_INTERVAL = int(os.getenv("POLL_INTERVAL_SECONDS", "60"))
FRONTEND_URL  = os.getenv("FRONTEND_URL")




async def _auto_poll():
    from pipeline import run_pipeline

    _state["poll_running"] = True
    logger.info(f"Auto-poller started (interval={POLL_INTERVAL}s)")

    while True:
        try:
            logger.info("Poller: fetching fresh alerts…")
            results = await run_pipeline()
            _state["cached_results"]    = results
            _state["last_poll_time"]    = datetime.now(timezone.utc).isoformat()
            _state["last_alert_count"]  = results.get("total_alerts", 0)
            _state["last_anomaly_count"] = results.get("anomaly_count", 0)
            logger.info(
                f"Poller: done — {results.get('total_alerts', 0)} alerts, "
                f"{results.get('anomaly_count', 0)} anomalies"
            )
        except Exception as exc:
            logger.error(f"Poller error: {exc}")

        await asyncio.sleep(POLL_INTERVAL)




@asynccontextmanager
async def lifespan(app: FastAPI):
    task = asyncio.create_task(_auto_poll())
    yield
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass




app = FastAPI(
    title="Wazuh-ATHEA API",
    description="Real-time Wazuh alert anomaly detection with ML + SHAP explainability",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[FRONTEND_URL],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(chatbot_router)




@app.get("/health", tags=["System"])
async def health():
    wazuh = await test_connection()
    return {
        "api_status": "ok",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "wazuh_indexer": wazuh,
    }


@app.get("/api/raw-alerts", tags=["Data"])
async def raw_alerts(
    minutes_back: int = Query(default=60, ge=1, le=1440,
                              description="How many minutes back to fetch alerts")
):
    try:
        alerts = await fetch_alerts(minutes_back=minutes_back)
        return {
            "count": len(alerts),
            "minutes_back": minutes_back,
            "alerts": alerts,
        }
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Wazuh Indexer error: {str(e)}")


@app.post("/api/analyze", tags=["Pipeline"])
async def analyze(
    minutes_back: int = Query(default=60, ge=1, le=1440,
                              description="Alert window in minutes")
):
    from pipeline import run_pipeline
    try:
        results = await run_pipeline(minutes_back=minutes_back)
        _state["cached_results"]     = results
        _state["last_poll_time"]     = datetime.now(timezone.utc).isoformat()
        _state["last_alert_count"]   = results.get("total_alerts", 0)
        _state["last_anomaly_count"] = results.get("anomaly_count", 0)
        return results
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/latest", tags=["Pipeline"])
async def latest():
    if _state["cached_results"] is None:
        raise HTTPException(
            status_code=503,
            detail="No results yet — pipeline is still running its first cycle."
        )
    return _state["cached_results"]


@app.get("/api/status", tags=["System"])
async def status():
    return {
        "poll_running":       _state["poll_running"],
        "poll_interval_sec":  POLL_INTERVAL,
        "last_poll_time":     _state["last_poll_time"],
        "last_alert_count":   _state["last_alert_count"],
        "last_anomaly_count": _state["last_anomaly_count"],
        "has_cached_results": _state["cached_results"] is not None,
    }




if __name__ == "__main__":
    port = int(os.getenv("BACKEND_PORT"))
    uvicorn.run("main:app", host="0.0.0.0", port=port, reload=True)
