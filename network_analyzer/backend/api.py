from fastapi import APIRouter, WebSocket, HTTPException
from pydantic import BaseModel
import asyncio
import sys
import os

# Ensure we can import backend modules from root
# sys.path.append(os.path.dirname(os.path.abspath(__file__))) 
# We rely on main.py setting up the path or running as a module
try:
    from web_app.backend.capture import capture_instance
except ImportError:
    # Fallback if running directly (testing)
    sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../')))
    from web_app.backend.capture import capture_instance

router = APIRouter()


@router.get("/interfaces")
async def list_interfaces():
    """Return network interfaces that tshark can capture on, enriched with psutil data."""
    import psutil
    import subprocess
    import re

    # Get psutil data for addresses and up/down status
    ps_stats = psutil.net_if_stats()
    ps_addrs = psutil.net_if_addrs()

    # Use tshark -D to get the list of capturable interfaces
    try:
        from pyshark.tshark.tshark import get_process_path
        tshark_path = get_process_path()
    except Exception:
        tshark_path = "tshark"

    interfaces = []
    try:
        result = subprocess.run(
            [tshark_path, "-D"], capture_output=True, text=True, timeout=5
        )
        for line in result.stdout.strip().split("\n"):
            line = line.strip()
            if not line:
                continue
            # Format: "4. \Device\NPF_{GUID} (Wi-Fi)"
            match = re.match(r"\d+\.\s+(.+?)\s+\((.+?)\)\s*$", line)
            if match:
                device = match.group(1).strip()
                friendly = match.group(2).strip()

                # Skip non-network captures (USB, ETW, etc.)
                if not device.startswith("\\Device\\NPF"):
                    continue

                # Enrich with psutil data
                addrs = ps_addrs.get(friendly, [])
                addresses = [a.address for a in addrs if a.family.name in ("AF_INET", "AF_INET6")]
                is_up = ps_stats.get(friendly) is not None and ps_stats[friendly].isup

                # Determine if this interface carries internet (public IP) traffic
                name_lower = friendly.lower()
                is_internet = (
                    "wi-fi" in name_lower or
                    "wifi" in name_lower or
                    name_lower.startswith("ethernet") or
                    name_lower.startswith("eth") or
                    name_lower.startswith("wlan") or
                    name_lower.startswith("en")  # macOS (en0, en1)
                ) and not any(v in name_lower for v in ["vmware", "virtual", "vpn", "loopback", "tailscale", "radmin"])

                interfaces.append({
                    "name": friendly,
                    "addresses": addresses,
                    "is_up": is_up,
                    "internet_facing": is_internet,
                })
    except Exception as e:
        print(f"tshark -D failed ({e}), falling back to psutil only")
        # Fallback: use psutil (may include non-capturable interfaces)
        for name, addr_list in ps_addrs.items():
            is_up = ps_stats.get(name) is not None and ps_stats[name].isup
            addresses = [a.address for a in addr_list if a.family.name in ("AF_INET", "AF_INET6")]
            interfaces.append({"name": name, "addresses": addresses, "is_up": is_up})

    # Sort: "up" interfaces first
    interfaces.sort(key=lambda x: (not x["is_up"], x["name"]))
    return {"interfaces": interfaces}


class StartCaptureRequest(BaseModel):
    interface: str

@router.post("/start_capture")
async def start_capture(req: StartCaptureRequest):
    if capture_instance.running:
        return {"status": "error", "message": "Capture already running"}
    
    # Check if loop and callback are set (should be set in main startup)
    if not capture_instance.loop or not capture_instance.callback:
         return {"status": "error", "message": "Backend not initialized properly (loop/callback missing)"}

    print(f"API request to start capture on {req.interface}")
    capture_instance.start_capture(req.interface, capture_instance.loop, capture_instance.callback)
    return {"status": "started", "interface": req.interface}

@router.post("/stop_capture")
async def stop_capture():
    if not capture_instance.running:
        return {"status": "error", "message": "Capture not running"}
    
    capture_instance.stop_capture()
    return {"status": "stopped"}

@router.get("/status")
async def get_status():
    return {"running": capture_instance.running, "interface": capture_instance.interface}

from fastapi import UploadFile, File
import shutil

@router.post("/analyze")
async def analyze_pcap(file: UploadFile = File(...)):
    # Lazy import to avoid crashing at startup if analysis deps are missing
    from web_app.backend.analysis import analyze_pcap_file
    temp_dir = "temp_uploads"
    os.makedirs(temp_dir, exist_ok=True)
    
    file_path = os.path.join(temp_dir, file.filename)
    csv_path = os.path.join(temp_dir, f"{file.filename}.csv")
    
    try:
        with open(file_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)
            
        results = analyze_pcap_file(file_path, csv_path)
        
        return {"filename": file.filename, "anomalies": results}
    except Exception as e:
        return {"error": str(e)}
    finally:
        # Cleanup could happen here or later
        pass


@router.get("/check_ip")
async def check_ip_reputation(ip: str = ""):
    """Check the AbuseIPDB reputation for a given IP address."""
    if not ip:
        return {"ip": ip, "skipped": True, "reason": "Missing 'ip' query parameter"}

    try:
        from web_app.backend.reputation import check_ip
        result = await check_ip(ip)
        return result
    except Exception as e:
        print(f"check_ip error for {ip}: {e}")
        return {"ip": ip, "skipped": True, "reason": str(e)}

# ─────────────────────────────────────────────
# SNAPSHOTS  (named manual saves)
# ─────────────────────────────────────────────
from typing import Dict, Any

@router.post("/scans")
async def save_snapshot(scan_data: Dict[Any, Any]):
    """Save a named snapshot of the current analysis."""
    from web_app.backend.database import Database
    try:
        snap_id = await Database.save_snapshot(scan_data)
        return {"status": "success", "scan_id": snap_id}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/scans")
async def list_snapshots():
    """List all saved snapshots (summary only, no heavy arrays)."""
    from web_app.backend.database import Database
    try:
        snaps = await Database.get_all_snapshots()
        return {"scans": snaps}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/scans/{snap_id}")
async def get_snapshot(snap_id: str):
    """Retrieve the full data for a specific snapshot."""
    from web_app.backend.database import Database
    try:
        snap = await Database.get_snapshot_by_id(snap_id)
        if not snap:
            raise HTTPException(status_code=404, detail="Snapshot not found")
        return snap
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.delete("/scans/{snap_id}")
async def delete_snapshot(snap_id: str):
    """Delete a snapshot."""
    from web_app.backend.database import Database
    try:
        success = await Database.delete_snapshot(snap_id)
        if not success:
            raise HTTPException(status_code=404, detail="Snapshot not found")
        return {"status": "success", "deleted": True}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# ─────────────────────────────────────────────
# DAILY LOGS  (auto-saved by capture)
# ─────────────────────────────────────────────

@router.get("/daily")
async def list_daily_dates():
    """Return all dates that have captured data, newest first."""
    from web_app.backend.database import Database
    try:
        dates = await Database.get_all_daily_dates()
        return {"dates": dates}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/daily/{date_str}")
async def get_daily_log(date_str: str, skip: int = 0, limit: int = 200):
    """
    Return a paginated slice of packets for a given date (YYYY-MM-DD).
    Use ?skip=0&limit=200 to page through large days.
    chartData and stats are always returned in full (they are small).
    """
    from web_app.backend.database import Database
    try:
        doc = await Database.get_daily_log_page(date_str, skip=skip, limit=limit)
        if not doc:
            raise HTTPException(status_code=404, detail="No data found for this date")
        total = await Database.get_daily_log_total(date_str)
        doc["_id"] = str(doc["_id"])
        doc["total_packets"] = total
        doc["skip"] = skip
        doc["limit"] = limit
        doc["has_more"] = (skip + limit) < total
        return doc
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/daily/{date_str}/meta")
async def get_daily_log_meta(date_str: str):
    """
    Fast aggregation endpoint — returns ALL dns queries + ALL unique IPs for a day
    without sending the full packets array. Used to populate DNS table and IP reputation
    queue when loading history.
    """
    from web_app.backend.database import Database
    try:
        meta = await Database.get_daily_log_meta(date_str)
        return meta
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.delete("/daily/{date_str}")
async def delete_daily_log(date_str: str):
    """Delete an entire day's captured log."""
    from web_app.backend.database import Database
    try:
        success = await Database.delete_daily_log(date_str)
        if not success:
            raise HTTPException(status_code=404, detail="No log found for this date")
        return {"status": "success", "deleted": True}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

