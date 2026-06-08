import asyncio
import sqlite3
import time
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor

try:
    import aiosqlite
    AIOSQLITE_OK = True
except ImportError:
    AIOSQLITE_OK = False

BATCH_COMMIT_SIZE = 100

class Archiver:
    def __init__(self, db_path):
        self.db_path = db_path
        self.listeners = set()
        self.is_running = False
        self.confirmed_count = 0
        self.scanned_count = 0
        self.skip_requested = False
        self.last_skipped_master = None
        self.current_network = "Awaiting..."
        self.last_status = "System Standby"
        self.current_region = "None"
        
        self.executor = ThreadPoolExecutor(max_workers=5)
        self.swarm_memory = {}
        self.SWARM_TTL = 1800
        
        # Async primitives
        self._write_queue = None
        self._manual_queue = None
        self._count_lock = None
        self._swarm_lock = None
        self._active_tasks_lock = None
        self.active_tasks = 0

    def _ensure_async_primitives(self):
        if self._write_queue is None:
            self._write_queue = asyncio.Queue(maxsize=50000)
        if self._manual_queue is None:
            self._manual_queue = asyncio.Queue()
        if self._count_lock is None:
            self._count_lock = asyncio.Lock()
        if self._swarm_lock is None:
            self._swarm_lock = asyncio.Lock()
        if self._active_tasks_lock is None:
            self._active_tasks_lock = asyncio.Lock()

    @property
    def write_queue(self):
        self._ensure_async_primitives(); return self._write_queue

    @property
    def manual_queue(self):
        self._ensure_async_primitives(); return self._manual_queue

    @property
    def count_lock(self):
        self._ensure_async_primitives(); return self._count_lock

    @property
    def swarm_lock(self):
        self._ensure_async_primitives(); return self._swarm_lock

    @property
    def active_tasks_lock(self):
        self._ensure_async_primitives(); return self._active_tasks_lock

    def init_db_sync(self):
        con = sqlite3.connect(self.db_path)
        con.execute("PRAGMA journal_mode=WAL")
        con.execute("""CREATE TABLE IF NOT EXISTS results (
            ip TEXT PRIMARY KEY, rir TEXT, cc TEXT, status TEXT, banner TEXT, vendor TEXT,
            working_url TEXT, codec TEXT, resolution TEXT, fps INTEGER, scanned_at TEXT,
            bookmarked INTEGER DEFAULT 0
        )""")
        cols = [row[1] for row in con.execute("PRAGMA table_info(results)").fetchall()]
        for c in ["codec", "resolution", "fps", "vendor", "bookmarked"]:
            if c not in cols:
                try: con.execute(f"ALTER TABLE results ADD COLUMN {c} {'INTEGER' if c in ['fps', 'bookmarked'] else 'TEXT'}")
                except: pass
        con.commit(); con.close()

    async def broadcast(self, event):
        if event["event"] == "status": self.last_status = event["msg"]
        if event["event"] == "network":
            self.current_network = event.get("net", "Unknown")
            self.current_region = f"{event.get('rir', '??')} | {event.get('cc', '??')}"
        
        # Ensure the event is a clean dictionary for JSON serialization
        clean_event = {}
        for k, v in event.items():
            if isinstance(v, (str, int, float, bool, type(None))):
                clean_event[k] = v
            else:
                clean_event[k] = str(v)

        dead = set()
        for q in list(self.listeners):
            try:
                q.put_nowait(clean_event)
            except asyncio.QueueFull:
                try: q.get_nowait()
                except: pass
                try: q.put_nowait(clean_event)
                except: pass
            except Exception:
                dead.add(q)
        self.listeners -= dead

    async def db_writer(self):
        if not AIOSQLITE_OK: return
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute("PRAGMA journal_mode=WAL")
            pending = 0
            while True:
                item = await self.write_queue.get()
                if item is None:
                    if pending: await db.commit()
                    break
                try:
                    if item.get("update"):
                        await db.execute(
                            "UPDATE results SET working_url=?,vendor=?,codec=?,resolution=?,fps=? WHERE ip=?",
                            (item["working_url"], item["vendor"], item["codec"], item.get("res"), item["fps"], item["ip"]))
                    else:
                        await db.execute(
                            "INSERT OR REPLACE INTO results (ip,rir,cc,status,banner,scanned_at) VALUES(?,?,?,?,?,?)",
                            (item["ip"], item["rir"], item["cc"], item["status"], item.get("banner"), item["ts"]))
                    pending += 1
                    if pending >= BATCH_COMMIT_SIZE or self.write_queue.empty():
                        await db.commit()
                        pending = 0
                except: pass

    async def event_generator(self):
        q = asyncio.Queue(maxsize=2000)
        self.listeners.add(q)
        try:
            yield {"event": "status", "msg": "Neural Link v8.8 Ready."}
            yield {"event": "progress", "scanned": self.scanned_count, "confirmed": self.confirmed_count}
            while True:
                try:
                    event = await asyncio.wait_for(q.get(), timeout=15.0)
                    yield event
                except asyncio.TimeoutError:
                    yield {"event": "ping"}
                except asyncio.CancelledError:
                    break
        finally:
            self.listeners.discard(q)
            
    async def increment_scanned(self):
        async with self.count_lock:
            self.scanned_count += 1
        return self.scanned_count

    async def increment_confirmed(self):
        async with self.count_lock:
            self.confirmed_count += 1
        return self.confirmed_count

    def inject_high_priority(self, target):
        self.manual_queue.put_nowait(target)
        self.skip_requested = True

    async def sync_favorites_txt(self):
        """Syncs all bookmarked IPs from DB to favorites.txt asynchronously."""
        def _sync():
            try:
                con = sqlite3.connect(self.db_path)
                rows = con.execute("SELECT ip FROM results WHERE bookmarked=1").fetchall()
                con.close()
                with open("favorites.txt", "w") as f:
                    for r in rows:
                        f.write(f"{r[0]}\n")
            except Exception as e:
                print(f"[ERROR SYNC TXT] {e}")
        
        await asyncio.get_running_loop().run_in_executor(self.executor, _sync)
