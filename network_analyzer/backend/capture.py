import pyshark
import threading
import asyncio
import json
import time
import sys
import os
from datetime import datetime

# Add project root to path so packet_classifier (and its packet_types imports) can be found
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../')))

try:
    from packet_classifier import classify_packet
    print("packet_classifier imported successfully.")
except ImportError as e:
    print(f"WARNING: packet_classifier not found ({e}). Using fallback classifier.")
    def classify_packet(packet):
        """Fallback classifier when packet_classifier module is unavailable."""
        info = {"Protocol": "Unknown", "Timestamp": ""}
        try:
            if hasattr(packet, 'ip'):
                info["Source IP"] = packet.ip.src
                info["Destination IP"] = packet.ip.dst
            if hasattr(packet, 'tcp'):
                info["Protocol"] = "TCP"
                info["Source Port"] = packet.tcp.srcport
                info["Destination Port"] = packet.tcp.dstport
            elif hasattr(packet, 'udp'):
                info["Protocol"] = "UDP"
                info["Source Port"] = packet.udp.srcport
                info["Destination Port"] = packet.udp.dstport
            elif hasattr(packet, 'icmp'):
                info["Protocol"] = "ICMP"
        except Exception:
            pass
        return info


# How often (seconds) to flush the packet buffer to MongoDB
DB_FLUSH_INTERVAL = 3


class PacketCapture:
    def __init__(self):
        self.running = False
        self.thread = None
        self.capture = None
        self.interface = None
        self.loop = None       # main FastAPI event loop
        self.callback = None   # WebSocket broadcast coroutine

        # Batch buffer for DB writes
        self._buffer_lock = threading.Lock()
        self._pending_packets: list = []     # raw packet dicts
        self._pending_chart: list = []       # chart time-series points
        self._pending_stats: dict = {"total": 0, "protocols": {}}

        # Last second seen for chart bucketing
        self._last_chart_time: str = ""

        # Flush task handle (asyncio.Task)
        self._flush_task = None

    # ─────────────────────────────────────────────
    # Public API
    # ─────────────────────────────────────────────

    def start_capture(self, interface, loop, callback):
        if self.running:
            return
        self.interface = interface
        self.loop = loop
        self.callback = callback
        self.running = True
        self._reset_buffer()

        # Schedule the periodic DB flush on the FastAPI event loop
        self._flush_task = asyncio.run_coroutine_threadsafe(
            self._periodic_flush(), loop
        )

        self.thread = threading.Thread(target=self._capture_loop, daemon=True)
        self.thread.start()

    def stop_capture(self):
        self.running = False
        if self.capture:
            try:
                self.capture.close()
            except Exception as e:
                print(f"Error closing capture: {e}")
        # Do one final flush synchronously via the main loop
        if self.loop and not self.loop.is_closed():
            future = asyncio.run_coroutine_threadsafe(self._flush_buffer(), self.loop)
            try:
                future.result(timeout=5)
                print("Final DB flush completed.")
            except Exception as e:
                print(f"Final flush error: {e}")

    # ─────────────────────────────────────────────
    # Buffer management
    # ─────────────────────────────────────────────

    def _reset_buffer(self):
        with self._buffer_lock:
            self._pending_packets = []
            self._pending_chart = []
            self._pending_stats = {"total": 0, "protocols": {}}
            self._last_chart_time = ""

    def _add_to_buffer(self, packet_info: dict):
        """Called from capture thread — NOT async."""
        protocol = packet_info.get("Protocol", "Unknown")
        ts_str = packet_info.get("Timestamp", "")
        # Use just H:M:S as the chart bucket key (same as frontend)
        try:
            bucket = datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S").strftime("%H:%M:%S")
        except Exception:
            bucket = datetime.now().strftime("%H:%M:%S")

        with self._buffer_lock:
            self._pending_packets.append(packet_info)
            self._pending_stats["total"] += 1
            self._pending_stats["protocols"][protocol] = (
                self._pending_stats["protocols"].get(protocol, 0) + 1
            )
            # Chart bucketing
            if self._last_chart_time == bucket and self._pending_chart:
                last = self._pending_chart[-1]
                last[protocol] = last.get(protocol, 0) + 1
                last["total"] = last.get("total", 0) + 1
            else:
                self._pending_chart.append({"time": bucket, "total": 1, protocol: 1})
                self._last_chart_time = bucket

    async def _flush_buffer(self):
        """Drain the buffer and persist to MongoDB."""
        with self._buffer_lock:
            if not self._pending_packets:
                return
            packets_batch = self._pending_packets[:]
            chart_batch = self._pending_chart[:]
            stats_delta = {
                "total": self._pending_stats["total"],
                "protocols": dict(self._pending_stats["protocols"]),
            }
            # Reset
            self._pending_packets = []
            self._pending_chart = []
            self._pending_stats = {"total": 0, "protocols": {}}
            self._last_chart_time = ""

        date_str = datetime.utcnow().strftime("%Y-%m-%d")
        try:
            from web_app.backend.database import Database
            await Database.upsert_daily_log(date_str, packets_batch, stats_delta, chart_batch)
            print(f"[DB] Flushed {len(packets_batch)} packets → daily log {date_str}")
        except Exception as e:
            print(f"[DB] Flush error: {e}")

    async def _periodic_flush(self):
        """Runs on the FastAPI event loop, flushing every DB_FLUSH_INTERVAL seconds."""
        while self.running:
            await asyncio.sleep(DB_FLUSH_INTERVAL)
            await self._flush_buffer()

    # ─────────────────────────────────────────────
    # Capture loop (runs in background thread)
    # ─────────────────────────────────────────────

    def _capture_loop(self):
        try:
            capture_loop = asyncio.new_event_loop()
            asyncio.set_event_loop(capture_loop)

            print(f"Initializing capture on {self.interface}")
            self.capture = pyshark.LiveCapture(interface=self.interface)

            print(f"Starting sniffing on {self.interface}...")

            for packet in self.capture.sniff_continuously():
                if not self.running:
                    print("Capture stopping requested.")
                    break

                try:
                    packet_info = classify_packet(packet)
                    if packet_info:
                        if not packet_info.get("Timestamp"):
                            packet_info["Timestamp"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

                        # Buffer for DB
                        self._add_to_buffer(packet_info)

                        # Broadcast to WebSocket clients
                        if self.loop and self.callback:
                            future = asyncio.run_coroutine_threadsafe(
                                self.callback(packet_info), self.loop
                            )
                            try:
                                future.result(timeout=0.5)
                            except Exception:
                                pass
                        else:
                            print("Loop or callback not set!")
                except Exception as e:
                    import traceback
                    print(f"Error processing packet: {e}")
                    traceback.print_exc()

        except Exception as e:
            import traceback
            print(f"Capture loop error: {e}")
            traceback.print_exc()
        finally:
            self.running = False
            if self.capture:
                try:
                    self.capture.close()
                except Exception:
                    pass
            print("Capture stopped.", flush=True)


capture_instance = PacketCapture()
