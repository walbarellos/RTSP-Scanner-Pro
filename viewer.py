import json
import os
import cv2
import requests
import time
import sqlite3
import argparse
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor

# --- Configuration ---
INPUT_FILE = "resultado.json"
DB_FILE = "rtsp_scan.db"
OUTPUT_HTML = "viewer.html"
SCREENSHOT_DIR = "screens"
GEO_API_URL = "http://ip-api.com/batch"
MAX_GEO_BATCH = 100
MAX_WORKERS = 20

def get_geo_data(ips):
    results = {}
    unique_ips = list(set(ips))
    for i in range(0, len(unique_ips), MAX_GEO_BATCH):
        batch = unique_ips[i:i + MAX_GEO_BATCH]
        try:
            response = requests.post(GEO_API_URL, json=batch)
            if response.status_code == 200:
                batch_data = response.json()
                for ip, data in zip(batch, batch_data):
                    if data.get("status") == "success":
                        results[ip] = {
                            "country": data.get("country", "Unknown"),
                            "city": data.get("city", "Unknown"),
                            "asn": data.get("as", "Unknown"),
                            "isp": data.get("isp", "Unknown")
                        }
        except Exception as e:
            print(f"[-] Error fetching geo data: {e}")
        if i + MAX_GEO_BATCH < len(unique_ips):
            time.sleep(4) 
    return results

def capture_frame(camera_info):
    url = camera_info["url"]
    ip = camera_info["ip"]
    port = camera_info["port"]
    
    fname = f"{ip.replace('.', '_')}_{port}.jpg"
    fpath = os.path.join(SCREENSHOT_DIR, fname)
    
    cap = cv2.VideoCapture(url)
    cap.set(cv2.CAP_PROP_OPEN_TIMEOUT_MSEC, 5000)
    
    success = False
    if cap.isOpened():
        ret, frame = cap.read()
        if ret:
            cv2.imwrite(fpath, frame)
            success = True
    
    cap.release()
    camera_info["file"] = fname if success else None
    print(f"{'[+]' if success else '[-]'} {url}")
    return camera_info

def build_html(grouped_cameras, total_count):
    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>RTSP Audit Report</title>
    <style>
        body {{ background: #0f0f0f; color: #d0d0d0; font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 0; padding: 20px; }}
        h1 {{ color: #00ff00; border-bottom: 2px solid #333; padding-bottom: 10px; }}
        .stats {{ margin-bottom: 20px; color: #888; font-size: 0.9em; }}
        .country-section {{ margin-bottom: 40px; border: 1px solid #333; border-radius: 8px; background: #1a1a1a; overflow: hidden; }}
        .country-header {{ background: #2a2a2a; padding: 15px; font-size: 1.5em; font-weight: bold; border-bottom: 1px solid #444; color: #fff; }}
        .asn-section {{ padding: 15px; border-bottom: 1px solid #222; }}
        .asn-header {{ color: #0080ff; font-weight: bold; margin-bottom: 10px; font-size: 1.1em; }}
        .grid {{ display: grid; grid-template-columns: repeat(auto-fill, minmax(300px, 1fr)); gap: 15px; }}
        .card {{ background: #111; border: 1px solid #333; border-radius: 6px; overflow: hidden; transition: transform 0.2s; }}
        .card:hover {{ transform: scale(1.02); border-color: #00ff00; }}
        .card img {{ width: 100%; height: 180px; object-fit: cover; background: #050505; }}
        .no-img {{ height: 180px; display: grid; place-items: center; background: #050505; color: #444; font-size: 0.8em; }}
        .info {{ padding: 12px; font-size: 0.85em; }}
        .info b {{ color: #00ff00; }}
        .info code {{ display: block; background: #000; padding: 5px; margin-top: 5px; border-radius: 3px; color: #aaa; word-break: break-all; }}
        .info .geo {{ color: #ff8000; margin-top: 5px; font-size: 0.9em; }}
        .info .rir {{ color: #888; font-size: 0.8em; margin-top: 3px; }}
        a {{ color: #4af; text-decoration: none; }}
        a:hover {{ text-decoration: underline; }}
    </style>
</head>
<body>
    <h1>🎥 RTSP Audit & Visualization Report</h1>
    <div class="stats">Found {total_count} streams across multiple targets.</div>
    """

    for country, asns in sorted(grouped_cameras.items()):
        html_content += f'<div class="country-section"><div class="country-header">🌍 {country}</div>'
        for asn, cameras in sorted(asns.items()):
            html_content += f'<div class="asn-section"><div class="asn-header">🏢 {asn}</div><div class="grid">'
            for cam in cameras:
                img_tag = f'<img src="{SCREENSHOT_DIR}/{cam["file"]}" loading="lazy">' if cam["file"] else "<div class='no-img'>[ NO FRAME CAPTURED ]</div>"
                rir_tag = f'<div class="rir">RIR: {cam["rir"]}</div>' if cam.get("rir") else ""
                html_content += f"""
                <div class="card">
                    {img_tag}
                    <div class="info">
                        <b>{cam['ip']}:{cam['port']}</b>
                        <div class="geo">📍 {cam.get('city', 'Unknown')}</div>
                        {rir_tag}
                        <code>{cam['url']}</code>
                        <div style="margin-top:8px;">
                            <a href="{cam['url']}" target="_blank">VLC / External</a> | 
                            <a href="http://localhost:8000/api/live?url={cam['url']}" target="_blank" style="color: #00ff00; font-weight: bold;">Watch Live (Browser)</a>
                        </div>
                    </div>
                </div>"""
            html_content += "</div></div>"
        html_content += "</div>"

    html_content += """
</body>
</html>"""
    return html_content

def load_from_json(path):
    with open(path) as f:
        data = json.load(f)
    cameras = []
    for item in data:
        ip = item.get("address", "")
        port = item.get("port", 554)
        user = item.get("username", "")
        pwd = item.get("password", "")
        routes = item.get("route", ["/"])
        for route in routes:
            url = f"rtsp://{user}:{pwd}@{ip}:{port}{route}" if user else f"rtsp://{ip}:{port}{route}"
            cameras.append({"ip": ip, "port": port, "url": url})
    return cameras

def load_from_db(path):
    con = sqlite3.connect(path)
    con.row_factory = sqlite3.Row
    rows = con.execute("SELECT ip, rir, cc, banner, working_url FROM results WHERE status='open'").fetchall()
    con.close()
    cameras = []
    for r in rows:
        cameras.append({
            "ip": r["ip"],
            "port": 554,
            "url": r["working_url"] or f"rtsp://{r['ip']}:554/",
            "rir": r["rir"],
            "country_code": r["cc"],
            "banner": r["banner"]
        })
    return cameras


def main():
    parser = argparse.ArgumentParser(description="RTSP Audit Viewer")
    parser.add_argument("--json", help="Path to JSON results", default=INPUT_FILE)
    parser.add_argument("--db", help="Path to SQLite results", default=None)
    args = parser.parse_args()

    raw_cameras = []
    if args.db and os.path.exists(args.db):
        print(f"[*] Loading from database: {args.db}")
        raw_cameras = load_from_db(args.db)
    elif os.path.exists(args.json):
        print(f"[*] Loading from JSON: {args.json}")
        raw_cameras = load_from_json(args.json)
    else:
        print("[-] No input file found. Specify --json or --db.")
        return

    os.makedirs(SCREENSHOT_DIR, exist_ok=True)
    
    ips_to_lookup = [cam["ip"] for cam in raw_cameras]
    print(f"[*] Fetching geolocation data for {len(set(ips_to_lookup))} unique IPs...")
    geo_results = get_geo_data(ips_to_lookup)

    print(f"[*] Starting parallel frame capture for {len(raw_cameras)} streams...")
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        processed_cameras = list(executor.map(capture_frame, raw_cameras))

    grouped = defaultdict(lambda: defaultdict(list))
    for cam in processed_cameras:
        geo = geo_results.get(cam["ip"], {})
        cam.update(geo)
        country = cam.get("country", cam.get("country_code", "Unknown"))
        asn = cam.get("asn", "Unknown ASN/ISP")
        grouped[country][asn].append(cam)

    print("[*] Generating HTML report...")
    with open(OUTPUT_HTML, "w", encoding="utf-8") as f:
        f.write(build_html(grouped, len(processed_cameras)))

    print(f"\n[+] Audit Complete! View: {os.path.abspath(OUTPUT_HTML)}")

if __name__ == "__main__":
    main()
