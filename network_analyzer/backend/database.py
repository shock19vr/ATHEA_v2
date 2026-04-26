import os
from motor.motor_asyncio import AsyncIOMotorClient
from datetime import datetime
from bson import ObjectId

MONGODB_URI = os.environ.get("MONGODB_URI", "mongodb://localhost:27017/")

class Database:
    client: AsyncIOMotorClient = None
    db = None

    @classmethod
    def connect_db(cls):
        print(f"Connecting to MongoDB at {MONGODB_URI}...")
        cls.client = AsyncIOMotorClient(MONGODB_URI)
        cls.db = cls.client.network_analyzer

    @classmethod
    def close_db(cls):
        if cls.client:
            print("Closing MongoDB connection...")
            cls.client.close()

    # ─────────────────────────────────────────────
    # DAILY LOGS  (one document per calendar day)
    # ─────────────────────────────────────────────

    @classmethod
    async def upsert_daily_log(cls, date_str: str, packets_batch: list, stats_delta: dict, chart_batch: list):
        """Atomically append packets and accumulate stats into today's document."""
        if cls.db is None:
            raise Exception("Database not initialized")

        protocol_inc = {
            f"stats.protocols.{proto}": count
            for proto, count in stats_delta.get("protocols", {}).items()
        }

        update = {
            "$push": {
                "packets": {"$each": packets_batch},
                "chartData": {"$each": chart_batch},
            },
            "$inc": {
                "stats.total": stats_delta.get("total", 0),
                **protocol_inc,
            },
            "$setOnInsert": {"date": date_str},
        }

        await cls.db.daily_logs.update_one(
            {"_id": date_str},
            update,
            upsert=True,
        )

    @classmethod
    async def get_all_daily_dates(cls):
        """Return list of dates (newest first) that have captured data."""
        if cls.db is None:
            raise Exception("Database not initialized")

        cursor = cls.db.daily_logs.find({}, {"_id": 1, "date": 1, "stats": 1}).sort("_id", -1)
        results = []
        async for doc in cursor:
            results.append({
                "date": doc.get("date", doc["_id"]),
                "stats": doc.get("stats", {}),
            })
        return results

    @classmethod
    async def get_daily_log_page(cls, date_str: str, skip: int = 0, limit: int = 200):
        """Return a paginated slice of packets for a given day."""
        if cls.db is None:
            raise Exception("Database not initialized")

        # Use $slice in the projection for efficient server-side pagination
        doc = await cls.db.daily_logs.find_one(
            {"_id": date_str},
            {
                "packets": {"$slice": [skip, limit]},
                "chartData": 1,
                "stats": 1,
                "date": 1,
            }
        )
        return doc

    @classmethod
    async def get_daily_log_total(cls, date_str: str) -> int:
        """Return the total packet count for a given day (no packet data fetched)."""
        if cls.db is None:
            raise Exception("Database not initialized")

        doc = await cls.db.daily_logs.find_one({"_id": date_str}, {"stats.total": 1})
        if doc:
            return doc.get("stats", {}).get("total", 0)
        return 0

    @classmethod
    async def get_daily_log(cls, date_str: str):
        """Return the full day document (all packets). Use sparingly for large days."""
        if cls.db is None:
            raise Exception("Database not initialized")

        doc = await cls.db.daily_logs.find_one({"_id": date_str})
        return doc

    @classmethod
    async def get_daily_log_meta(cls, date_str: str) -> dict:
        """
        Return ALL dns queries and ALL unique IPs from a day using aggregation —
        without fetching every packet. Very fast even for large daily logs.
        """
        if cls.db is None:
            raise Exception("Database not initialized")

        pipeline = [
            {"$match": {"_id": date_str}},
            {"$project": {"packets": 1}},
            {"$unwind": "$packets"},
            {"$facet": {
                # DNS: only packets where Protocol == "DNS" and Query Name exists
                "dns_queries": [
                    {"$match": {
                        "packets.Protocol": "DNS",
                        "packets.Query Name": {"$exists": True, "$ne": ""}
                    }},
                    {"$replaceRoot": {"newRoot": "$packets"}},
                    {"$limit": 500},  # cap at 500 DNS entries for sanity
                ],
                # Unique IPs: collect all src + dst IPs as a flat deduplicated set
                "source_ips": [
                    {"$match": {"packets.Source IP": {"$exists": True, "$ne": ""}}},
                    {"$group": {"_id": "$packets.Source IP"}},
                    {"$limit": 300},
                ],
                "dest_ips": [
                    {"$match": {"packets.Destination IP": {"$exists": True, "$ne": ""}}},
                    {"$group": {"_id": "$packets.Destination IP"}},
                    {"$limit": 300},
                ],
            }},
        ]

        results = []
        async for doc in cls.db.daily_logs.aggregate(pipeline):
            results.append(doc)

        if not results:
            return {"dns_queries": [], "unique_ips": []}

        facet = results[0]
        src_ips = [d["_id"] for d in facet.get("source_ips", [])]
        dst_ips = [d["_id"] for d in facet.get("dest_ips", [])]
        unique_ips = list(set(src_ips + dst_ips))

        return {
            "dns_queries": facet.get("dns_queries", []),
            "unique_ips": unique_ips,
        }


    @classmethod
    async def delete_daily_log(cls, date_str: str):
        """Delete an entire day's log."""
        if cls.db is None:
            raise Exception("Database not initialized")

        result = await cls.db.daily_logs.delete_one({"_id": date_str})
        return result.deleted_count > 0

    # ─────────────────────────────────────────────
    # SNAPSHOTS  (named manual saves)
    # ─────────────────────────────────────────────

    @classmethod
    async def save_snapshot(cls, data: dict):
        """Save a named snapshot of the current analysis."""
        if cls.db is None:
            raise Exception("Database not initialized")

        data["timestamp"] = datetime.utcnow()
        result = await cls.db.snapshots.insert_one(data)
        return str(result.inserted_id)

    @classmethod
    async def get_all_snapshots(cls):
        """Return summary list of snapshots (no packet arrays)."""
        if cls.db is None:
            raise Exception("Database not initialized")

        cursor = cls.db.snapshots.find({}, {"name": 1, "timestamp": 1, "stats": 1}).sort("timestamp", -1)
        results = []
        async for doc in cursor:
            doc["_id"] = str(doc["_id"])
            results.append(doc)
        return results

    @classmethod
    async def get_snapshot_by_id(cls, snapshot_id: str):
        """Return full snapshot document."""
        if cls.db is None:
            raise Exception("Database not initialized")

        doc = await cls.db.snapshots.find_one({"_id": ObjectId(snapshot_id)})
        if doc:
            doc["_id"] = str(doc["_id"])
        return doc

    @classmethod
    async def delete_snapshot(cls, snapshot_id: str):
        """Delete a snapshot."""
        if cls.db is None:
            raise Exception("Database not initialized")

        result = await cls.db.snapshots.delete_one({"_id": ObjectId(snapshot_id)})
        return result.deleted_count > 0

    # ─────────────────────────────────────────────
    # BACKWARD COMPAT aliases (old /scans endpoints)
    # ─────────────────────────────────────────────
    @classmethod
    async def save_scan(cls, data): return await cls.save_snapshot(data)

    @classmethod
    async def get_all_scans_summary(cls): return await cls.get_all_snapshots()

    @classmethod
    async def get_scan_by_id(cls, sid): return await cls.get_snapshot_by_id(sid)

    @classmethod
    async def delete_scan(cls, sid): return await cls.delete_snapshot(sid)


db = Database()
