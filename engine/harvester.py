import requests
import math
import ipaddress
import asyncio
import random

# --- Config & Constants ---
FEEDS = {
    "ARIN":    "https://ftp.arin.net/pub/stats/arin/delegated-arin-extended-latest",
    "RIPE":    "https://ftp.ripe.net/pub/stats/ripencc/delegated-ripencc-extended-latest",
    "AFRINIC": "https://ftp.afrinic.net/pub/stats/afrinic/delegated-afrinic-extended-latest",
    "APNIC":   "https://ftp.apnic.net/stats/apnic/delegated-apnic-extended-latest",
}

HOT_CC = ["CN", "KR", "JP", "TW", "RU", "UA", "TR", "IN", "IR"]
HOT_NETWORKS = ["116.0.0.0/8", "222.0.0.0/8", "114.0.0.0/8", "121.0.0.0/8", "185.0.0.0/8", "109.0.0.0/8", "218.0.0.0/8"]

def is_public_ip(ip_str):
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        return not (ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_multicast or ip_obj.is_reserved or str(ip_obj).startswith("0."))
    except: return False

def fragment_network(net_str, target_prefix=20):
    """Fragmenta a rede em blocos /20 (max ~4096 hosts cada)."""
    try:
        net = ipaddress.ip_network(net_str, False)
        if net.prefixlen >= target_prefix:
            return [str(net)]
        return [str(s) for s in net.subnets(new_prefix=target_prefix)]
    except:
        return []

async def fetch_all_feeds(broadcast_callback=None):
    """Sync feeds from RIRs concurrently and yield targets as soon as each RIR is ready."""
    loop = asyncio.get_running_loop()

    def _parse_rir_content(rir, text):
        parsed = []
        for line in text.splitlines():
            if "|ipv4|" not in line: continue
            p = line.split("|")
            if len(p) < 7 or p[3] == "*": continue
            cc = p[1]
            if cc == "US": continue 
            try:
                count = int(p[4])
                if count < 1: continue
                prefix = 32 - int(math.log2(count))
                prefix = max(0, min(32, prefix))
                net_str = f"{p[3]}/{prefix}"
                if not is_public_ip(p[3]): continue
                priority = 10 if cc in HOT_CC or rir == "RIPE" else 1
                parsed.append((priority, rir, cc, net_str, net_str))
            except: continue
        return parsed

    async def _fetch_and_compile_rir(rir, url):
        if broadcast_callback:
            await broadcast_callback({"event": "status", "msg": f"Contacting {rir}..."})
        try:
            r = await loop.run_in_executor(None, lambda u=url: requests.get(u, timeout=12))
            if broadcast_callback:
                await broadcast_callback({"event": "status", "msg": f"Compiling {rir} Targets..."})
            
            raw_nets = await loop.run_in_executor(None, _parse_rir_content, rir, r.text)
            
            def _compile_internal(nets):
                fragged = []
                for prio, rir_name, cc, net_str, master in nets:
                    for f in fragment_network(net_str):
                        fragged.append((prio, rir_name, cc, f, master))
                random.shuffle(fragged)
                fragged.sort(key=lambda x: x[0], reverse=True)
                return fragged

            return await loop.run_in_executor(None, _compile_internal, raw_nets)
        except Exception as e:
            if broadcast_callback:
                await broadcast_callback({"event": "status", "msg": f"{rir} skipped: {str(e)[:30]}"})
            return []

    # Concurrent fetch using as_completed to yield as soon as the FASTEST RIR finishes
    fetch_tasks = [asyncio.create_task(_fetch_and_compile_rir(rir, url)) for rir, url in FEEDS.items()]
    
    for task in asyncio.as_completed(fetch_tasks):
        rir_targets = await task
        for target in rir_targets:
            yield target

    if broadcast_callback:
        await broadcast_callback({"event": "status", "msg": "Intelligence deployment cycle complete."})




