import sqlite3
import yaml
import os

def generate_config():
    db_path = "rtsp_scan.db"
    config_file = "go2rtc.yaml"
    
    if not os.path.exists(db_path):
        print("[-] Erro: Banco de dados não encontrado.")
        return

    con = sqlite3.connect(db_path)
    con.row_factory = sqlite3.Row
    # Pega apenas as câmeras abertas e confirmadas
    rows = con.execute("SELECT ip, cc, working_url FROM results WHERE status='open'").fetchall()
    con.close()

    streams = {}
    for r in rows:
        name = f"{r['cc']}_{r['ip'].replace('.', '_')}"
        url = r['working_url'] or f"rtsp://{r['ip']}:554/"
        codec = (r['codec'] or "").upper()
        
        # if codec is H264 or HEVC, we can optionally force ffmpeg with GPU accel
        # but passthrough is usually better. We will provide both options in the YAML.
        if codec in ["H264", "HEVC"]:
            streams[name] = [
                url, # First choice: direct passthrough (zero transcode)
                f"ffmpeg:{url}#video={codec.lower()}" # Second choice: GPU accelerated transcode if needed
            ]
        else:
            streams[name] = [url]

    # Add ffmpeg hardware acceleration config
    config = {
        "ffmpeg": {
            "bin": "ffmpeg",
            "global": "-hwaccel cuda -hwaccel_output_format cuda"
        },
        "streams": streams
    }

    with open(config_file, "w") as f:
        yaml.dump(config, f, default_flow_style=False)
    
    print(f"[+] {len(streams)} câmeras indexadas em {config_file}")
    print("[!] Agora você pode rodar o binário do go2rtc nesta pasta.")

if __name__ == "__main__":
    generate_config()
