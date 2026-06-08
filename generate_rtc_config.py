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
    # Pega apenas as câmeras favoritadas (Mission Book)
    rows = con.execute("SELECT ip, cc, working_url, codec FROM results WHERE bookmarked=1").fetchall()
    con.close()

    if not rows:
        print("[!] Nenhuma câmera favoritada encontrada. Mission Wall estará vazio.")

    streams = {}
    for r in rows:
        name = f"{r['cc']}_{r['ip'].replace('.', '_')}"
        url = r['working_url'] or f"rtsp://{r['ip']}:554/"
        codec = (r['codec'] or "h264").lower()
        
        # Dual source logic: direct and transcode
        streams[name] = [
            url,
            f"ffmpeg:{url}#video={codec}"
        ]

    # COMPACT CONFIG FOR MAXIMUM COMPATIBILITY
    config = {
        "api": {
            "origin": "*" # Allow any origin (CORS fix)
        },
        "webrtc": {
            "ice_servers": [
                {"urls": ["stun:stun.l.google.com:19302"]}
            ]
        },
        "ffmpeg": {
            "bin": "ffmpeg",
            "global": "-hwaccel cuda -hwaccel_output_format cuda"
        },
        "streams": streams
    }

    with open(config_file, "w") as f:
        yaml.dump(config, f, default_flow_style=False)
    
    print(f"[+] {len(streams)} câmeras configuradas em {config_file}")
    print("[!] REINICIE O GO2RTC PARA APLICAR AS MUDANÇAS.")

if __name__ == "__main__":
    generate_config()
