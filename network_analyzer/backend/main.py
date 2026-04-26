from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
import sys
import os
import asyncio
import json

# Add parent directory to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../')))

# Load .env — project root first, then backend dir (override=True so real key wins over placeholder)
from dotenv import load_dotenv, find_dotenv
_backend_dir = os.path.dirname(os.path.abspath(__file__))
_project_root = os.path.abspath(os.path.join(_backend_dir, '../../'))
load_dotenv(find_dotenv(), override=True)
load_dotenv(os.path.join(_project_root, '.env'), override=True)
load_dotenv(os.path.join(_backend_dir, '.env'), override=True)  # most specific wins

_api_key = os.environ.get('ABUSEIPDB_API_KEY', '')
if _api_key and _api_key != 'your_api_key_here':
    print(f"✓ AbuseIPDB API key loaded (length: {len(_api_key)})")
else:
    print("⚠ AbuseIPDB API key NOT found — IP reputation checks will be skipped")

from web_app.backend.api import router as api_router
from web_app.backend.capture import capture_instance
from web_app.backend.database import Database

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class ConnectionManager:
    def __init__(self):
        self.active_connections: list[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        self.active_connections.remove(websocket)

    async def broadcast(self, message: dict):
        # Broadcast JSON message to all active connections
        txt = json.dumps(message)
        dead_connections = []
        for connection in self.active_connections:
            try:
                await connection.send_text(txt)
            except Exception:
                dead_connections.append(connection)
        # Remove dead connections
        for dc in dead_connections:
            try:
                self.active_connections.remove(dc)
            except ValueError:
                pass

manager = ConnectionManager()

@app.get("/")
async def root():
    return {"message": "Network Analyzer API is running"}

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)

# Configure capture instance with the broadcast callback
@app.on_event("startup")
async def startup_event():
    loop = asyncio.get_running_loop()
    # We pass a lambda that calls manager.broadcast
    # And we need to ensure packet_info is serializable
    capture_instance.loop = loop
    capture_instance.callback = manager.broadcast
    
    # Initialize MongoDB connection
    Database.connect_db()

@app.on_event("shutdown")
async def shutdown_event():
    capture_instance.stop_capture()
    Database.close_db()

app.include_router(api_router, prefix="/api")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
