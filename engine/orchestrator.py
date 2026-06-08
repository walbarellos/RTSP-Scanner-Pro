import asyncio
import random
import sqlite3
import ipaddress
from datetime import datetime
from .harvester import fetch_all_feeds
from .probe import probe_ip, run_deep_probe

MAX_WORKERS = 10
CONNECT_TIMEOUT = 3.0

async def run_scan(archiver):
    if archiver.is_running: return
    archiver.is_running = True
    
    try:
        archiver.init_db_sync()
        semaphore = asyncio.Semaphore(MAX_WORKERS)
        writer_task = asyncio.create_task(archiver.db_writer())

        async def watchdog():
            while archiver.is_running:
                await archiver.broadcast({"event": "status", "msg": f"Pulse: {archiver.scanned_count} audited..."})
                await asyncio.sleep(15)
        asyncio.create_task(watchdog())

        # Load skip cache
        with sqlite3.connect(archiver.db_path) as con:
            skip_ips = {row[0] for row in con.execute("SELECT ip FROM results WHERE status IN ('open','closed')")}
        
        await archiver.broadcast({"event": "status", "msg": f"🚀 v8.8 Ready. ({len(skip_ips)} targets cached)"})

        # --- CRITICAL FIX: Launch manual handler BEFORE RIR sync ---
        async def manual_handler():
            while archiver.is_running:
                try:
                    m_target = await asyncio.wait_for(archiver.manual_queue.get(), timeout=0.5)
                    await archiver.broadcast({"event": "status", "msg": f"⚡ DIRECT JUMP: {m_target}"})
                    await _scan_single_net(m_target, "MANUAL", "USER", m_target, archiver, semaphore, skip_ips, force=True)
                except asyncio.TimeoutError:
                    continue
                except Exception as e:
                    print(f"[MANUAL ERROR] {e}")

        asyncio.create_task(manual_handler())

        # 1. Fetch targets incrementally (generator)
        async for prio, rir, cc, net_str, master in fetch_all_feeds(archiver.broadcast):
            if not archiver.is_running: break
            
            if archiver.last_skipped_master == master: continue
            
            await _scan_single_net(net_str, rir, cc, master, archiver, semaphore, skip_ips)
            
            if archiver.skip_requested:
                archiver.skip_requested = False
                archiver.last_skipped_master = master
            
            await asyncio.sleep(0)

        await archiver.write_queue.put(None)
        await writer_task
    finally:
        archiver.is_running = False



async def _worker(target_ip, rir, cc, archiver, semaphore):
    async with archiver.active_tasks_lock:
        archiver.active_tasks += 1
    
    try:
        res = await probe_ip(target_ip, 554, CONNECT_TIMEOUT, rir, cc)
        if res:
            if res["status"] == "open":
                await archiver.broadcast({"event": "found_hw", "ip": target_ip, "rir": rir, "cc": cc, "banner": res["banner"][:250]})
                
                async def on_success(ip, url, rir, cc, banner, vendor, meta):
                    confirmed = await archiver.increment_confirmed()
                    print(f"[HIT] {ip} | {vendor} | {meta['res']}")
                    await archiver.broadcast({"event": "confirmed", "ip": ip, "url": url, "rir": rir, "cc": cc, "banner": banner, "vendor": vendor, **meta})
                    await archiver.write_queue.put({"ip": ip, "working_url": url, "vendor": vendor, "update": True, **meta})

                asyncio.create_task(run_deep_probe(
                    target_ip, 554, rir, cc, res["banner"], archiver.executor, 
                    archiver.swarm_memory, archiver.swarm_lock, archiver.SWARM_TTL, on_success
                ))
            
            ts = datetime.utcnow().isoformat()
            await archiver.write_queue.put({**res, "ts": ts})
            
        scanned = await archiver.increment_scanned()
        # High frequency updates at start, then throttle
        if scanned <= 20 or scanned % 10 == 0:
            await archiver.broadcast({"event": "progress", "scanned": archiver.scanned_count, "confirmed": archiver.confirmed_count})
        elif scanned % 50 == 0:
            await archiver.broadcast({"event": "progress", "scanned": archiver.scanned_count, "confirmed": archiver.confirmed_count})
    finally:
        async with archiver.active_tasks_lock:
            archiver.active_tasks -= 1

async def _scan_single_net(net_str, rir, cc, master, archiver, semaphore, skip_ips, force=False):
    if not force:
        await archiver.broadcast({"event": "network", "net": str(net_str), "rir": rir, "cc": cc})
    else:
        # Immediate UI feedback for manual jump
        await archiver.broadcast({"event": "found_hw", "ip": net_str, "rir": "MANUAL", "cc": "USER", "banner": "Interrogating manual target..."})
        
    try:
        network = ipaddress.ip_network(net_str, False)
        if network.prefixlen == 32:
            hosts = [network.network_address]
        elif network.prefixlen == 31:
            hosts = list(network)
        else:
            hosts = list(network.hosts())
        random.shuffle(hosts)
        
        for ip in hosts:
            if not archiver.is_running: return
            # Only allow skip requested and manual check interruption for non-forced scans
            if not force and (archiver.skip_requested or not archiver.manual_queue.empty()):
                return
            
            ip_s = str(ip)
            if not force and ip_s in skip_ips: continue
            
            asyncio.create_task(_worker(ip_s, rir, cc, archiver, semaphore))
            if not force: skip_ips.add(ip_s) # Local cache update
            
            # Pacing delay to prevent network/CPU spikes
            await asyncio.sleep(0.1)
            
            # Manual jumps bypass this throttle loop
            if not force:
                while archiver.active_tasks > MAX_WORKERS:
                    await asyncio.sleep(0.1)
    except: pass
