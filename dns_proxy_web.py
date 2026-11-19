import collections
import contextlib
import dataclasses
import io
import json
import math
import os
import platform
import re
import socket
import subprocess
import sys
import threading
import time
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

import dns_proxy as dp

HTML_PATH = os.path.join(dp.BASE_DIR, "dashboard.html")
MAX_BODY = 8192
MAX_DOMAIN_INPUT = 512


_PING_TIME = re.compile(r"[=<]\s*(\d+(?:[.,]\d+)?)\s*ms", re.I)


def measure_ping(host, timeout=2.0, tcp_ports=(443, 53, 80)):
    
    result = {"host": host, "ok": False, "ms": None, "method": None}
    if not dp.is_ipv4(host):
        return result
    system = platform.system()
    if system == "Windows":
        cmd = ["ping", "-n", "1", "-w", str(int(timeout * 1000)), host]
    elif system == "Darwin":
        cmd = ["ping", "-c", "1", "-W", str(int(timeout * 1000)), host]
    else:
        cmd = ["ping", "-c", "1", "-W", str(max(1, int(math.ceil(timeout)))), host]
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, errors="replace",
                             timeout=timeout + 2.5).stdout
        match = _PING_TIME.search(out)
        if match:
            result.update(ok=True, ms=round(float(match.group(1).replace(",", ".")), 2), method="icmp")
            return result
    except (OSError, subprocess.SubprocessError):
        pass
    for port in tcp_ports:                                                    
        t0 = time.perf_counter()
        try:
            with socket.create_connection((host, port), timeout=timeout):
                pass
        except OSError:
            continue
        result.update(ok=True, ms=round((time.perf_counter() - t0) * 1000.0, 2), method="tcp")
        return result
    return result


                                                                           
KEY_ALIASES = {
    "entries_max_cache": ("entries_max_cache", "cache_max_entries"),
    "real_dns_enabled": ("real_dns_enabled", "enabled_dns_real"),
}


class Backend:
    def __init__(self, proxy, cfg_path=None):
        self.proxy = proxy
        self.cfg_path = cfg_path                                                      
        self.lock = threading.Lock()                                                   
        self.reload_lock = threading.Lock()
        self.history = collections.deque(maxlen=200)
        self.last_cache = []
        self.upstream = None
        self.log = []
        self.log_lock = threading.Lock()
        self.boot_time = time.time()
        self.server_ping = {"host": proxy.cfg.upstream_ip, "ok": False, "ms": None, "method": None}
        threading.Thread(target=self._ping_loop, daemon=True).start()

    def _ping_loop(self):
        
        while True:
            self.server_ping = dict(measure_ping(self.proxy.cfg.upstream_ip), at=time.time())
            time.sleep(5)

                                                                              
    def resolve(self, text):
        t0 = time.perf_counter()
        with self.lock:
            result = self.proxy.resolve(text)
            self.proxy.record(result)
        item = {"t": time.time(), "domain": result.domain, "source": result.source,
                "status": result.status, "ip": result.ip, "ttl": result.ttl,
                "ms": round((time.perf_counter() - t0) * 1000.0, 2)}
        self.history.append(item)
        return item

    def cache_snapshot(self):
        if self.lock.acquire(blocking=False):                                             
            try:
                self.proxy._purge_expired()
                now = time.monotonic()
                self.last_cache = [
                    {"domain": name, "ip": entry[0], "left": self.proxy._remaining(entry, now), "ttl": entry[1]}
                    for name, entry in self.proxy.cache.items()]
            finally:
                self.lock.release()
        return self.last_cache

    def clear_cache(self):
        with self.lock:
            self.proxy.cache.clear()
        self.last_cache = []

                                                                              
    def state(self):
        p, c = self.proxy, self.proxy.cfg
        return {
            "config": {
                "upstream": f"{c.upstream_ip}:{c.upstream_port}",
                "mode": "real_dns" if c.real_dns_enabled else "text_udp",
                "timeout": c.upstream_timeout_sec,
                "cache_enabled": c.cache_enabled,
                "cache_max": c.entries_max_cache,
                "sinkhole_ip": c.sinkhole_ip,
                "proxy_ip": c.proxy_ip,
                "local_ttl": c.local_ttl,
                "ad_count": len(p.ad_list),
                "sanction_count": len(p.sanction_list),
            },
            "stats": dict(p.stats),
            "cache": self.cache_snapshot(),
            "upstream": {"managed": not c.real_dns_enabled, "running": self.upstream_running()},
            "ping": self.server_ping,
            "log_len": len(self.log),
            "uptime": int(time.time() - self.boot_time),
            "busy": self.lock.locked(),
        }

                                                                              
    def upstream_running(self):
        return self.upstream is not None and self.upstream.poll() is None

    def _pump(self, proc):
        for line in proc.stdout:
            with self.log_lock:
                self.log.append(line.rstrip("\n"))
                del self.log[:-1000]

    def _log(self, line):
        with self.log_lock:
            self.log.append(line)

    def upstream_control(self, action):
        if action == "stop":
            if self.upstream_running():
                self.upstream.terminate()
                self._log("--- mock upstream stopped ---")
            self.upstream = None
        elif action == "start":
            if self.upstream_running():
                return
            path = os.path.join(dp.BASE_DIR, "upstream.py")
            self.upstream = subprocess.Popen(
                [sys.executable, "-u", path], cwd=dp.BASE_DIR, stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT, text=True, encoding="utf-8", errors="replace")
            threading.Thread(target=self._pump, args=(self.upstream,), daemon=True).start()
        else:
            raise ValueError("action must be start or stop")

    def log_since(self, since):
        with self.log_lock:
            return {"lines": self.log[since:], "next": len(self.log)}

                                                                              
    def get_settings(self):
        c = self.proxy.cfg
        return {
            "real_dns_enabled": c.real_dns_enabled,
            "upstream_ip": c.upstream_ip,
            "upstream_port": c.upstream_port,
            "upstream_timeout_sec": c.upstream_timeout_sec,
            "cache_enabled": c.cache_enabled,
            "entries_max_cache": c.entries_max_cache,
            "sinkhole_ip": c.sinkhole_ip,
            "proxy_ip": c.proxy_ip,
            "local_ttl": c.local_ttl,
            "ad_list_file": c.ad_list_file,
            "sanction_list_file": c.sanction_list_file,
            "config_file": os.path.basename(self.cfg_path) if self.cfg_path else None,
        }

    @staticmethod
    def _validated(data, old):
        
        def text(key):
            value = data.get(key, getattr(old, key))
            return str(value).strip()

        def boolean(key):
            value = data.get(key, getattr(old, key))
            if isinstance(value, bool):
                return value
            return dp._as_bool(key, str(value).strip())

        timeout = text("upstream_timeout_sec")
        if not dp._UFLOAT.fullmatch(timeout) or float(timeout) <= 0:
            raise dp.ConfigError(f"'upstream_timeout_sec' must be a positive number, got '{timeout}'")
        for key in ("ad_list_file", "sanction_list_file"):
            if not text(key):
                raise dp.ConfigError(f"'{key}' must not be empty")
        return dataclasses.replace(
            old,
            upstream_ip=dp._as_ipv4("upstream_ip", text("upstream_ip")),
            upstream_port=dp._as_int("upstream_port", text("upstream_port"), 1, 65535),
            upstream_timeout_sec=float(timeout),
            sinkhole_ip=dp._as_ipv4("sinkhole_ip", text("sinkhole_ip")),
            proxy_ip=dp._as_ipv4("proxy_ip", text("proxy_ip")),
            local_ttl=dp._as_int("local_ttl", text("local_ttl"), 0),
            cache_enabled=boolean("cache_enabled"),
            entries_max_cache=dp._as_int("entries_max_cache", text("entries_max_cache"), 0),
            real_dns_enabled=boolean("real_dns_enabled"),
            ad_list_file=text("ad_list_file"),
            sanction_list_file=text("sanction_list_file"),
        )

    def apply_settings(self, data, save=False):
        
        old = self.proxy.cfg
        try:
            new = self._validated(data, old)
            lists = None
            if (new.ad_list_file, new.sanction_list_file) != (old.ad_list_file, old.sanction_list_file):
                with contextlib.redirect_stdout(io.StringIO()):
                    lists = (dp.load_list(new.ad_list_file), dp.load_list(new.sanction_list_file))
        except dp.ConfigError as exc:
            raise ValueError(str(exc))

        upstream_changed = (new.real_dns_enabled, new.upstream_ip, new.upstream_port) != \
                           (old.real_dns_enabled, old.upstream_ip, old.upstream_port)
        with self.lock:                                                                
            self.proxy.cfg = new
            if lists:
                self.proxy.ad_list, self.proxy.sanction_list = lists
            if upstream_changed or not new.cache_enabled:
                self.proxy.cache.clear()                                                        
        self.last_cache = []
        self.server_ping = {"host": new.upstream_ip, "ok": False, "ms": None, "method": None}

        notes = []
        if new.real_dns_enabled:
            if self.upstream_running():                                                     
                self.upstream_control("stop")
                notes.append("mock upstream stopped")
        elif not self.upstream_running():
            try:
                self.upstream_control("start")
                notes.append("mock upstream started")
            except OSError as exc:
                notes.append(f"could not start mock upstream: {exc}")
        if save:
            self.save_config_file(new)
            notes.append(f"saved to {os.path.basename(self.cfg_path)}")
        return {"settings": self.get_settings(), "notes": notes}

    def save_config_file(self, cfg):
        
        if not self.cfg_path:
            raise ValueError("no config file to save to")
        values = {
            "upstream_ip": cfg.upstream_ip, "upstream_port": cfg.upstream_port,
            "upstream_timeout_sec": f"{cfg.upstream_timeout_sec:g}",
            "sinkhole_ip": cfg.sinkhole_ip, "proxy_ip": cfg.proxy_ip, "local_ttl": cfg.local_ttl,
            "ad_list_file": cfg.ad_list_file, "sanction_list_file": cfg.sanction_list_file,
            "cache_enabled": str(cfg.cache_enabled).lower(),
            "entries_max_cache": cfg.entries_max_cache,
            "real_dns_enabled": str(cfg.real_dns_enabled).lower(),
        }
        alias_of = {a: canon for canon, names in KEY_ALIASES.items() for a in names}
        with open(self.cfg_path, encoding="utf-8-sig") as f:
            lines = f.read().splitlines()
        done = set()
        for i, line in enumerate(lines):
            stripped = line.strip()
            if not stripped or stripped.startswith("#") or "=" not in stripped:
                continue
            key = stripped.split("=", 1)[0].strip()
            canon = alias_of.get(key.lower(), key.lower())
            if canon in values and canon not in done:
                lines[i] = f"{key}={values[canon]}"
                done.add(canon)
        for canon, value in values.items():
            if canon not in done:
                lines.append(f"{canon}={value}")
        tmp = self.cfg_path + ".tmp"
        with open(tmp, "w", encoding="utf-8", newline="\n") as f:
            f.write("\n".join(lines) + "\n")
        os.replace(tmp, self.cfg_path)

                                                                              
    def lists(self):
        return {"ad": sorted(self.proxy.ad_list), "sanction": sorted(self.proxy.sanction_list)}

    def reload_lists(self):
        buf = io.StringIO()
        with self.reload_lock:
            try:
                with contextlib.redirect_stdout(buf):
                    ads = dp.load_list(self.proxy.cfg.ad_list_file)
                    sanctions = dp.load_list(self.proxy.cfg.sanction_list_file)
            except dp.ConfigError as exc:
                raise ValueError(f"reload failed: {exc}")
            self.proxy.ad_list, self.proxy.sanction_list = ads, sanctions
        warnings = [l for l in buf.getvalue().splitlines() if l.strip()]
        return {"ad": len(ads), "sanction": len(sanctions), "warnings": warnings}

    def add_to_list(self, which, domain):
        if which not in ("ad", "sanction"):
            raise ValueError("list must be 'ad' or 'sanction'")
        domain = domain.strip()
        if not dp.is_valid_domain(domain):
            raise ValueError("not a valid domain")
        name = dp.normalize(domain)
        cfg = self.proxy.cfg
        current = self.proxy.ad_list if which == "ad" else self.proxy.sanction_list
        if name not in current:
            path = dp.resolve_path(cfg.ad_list_file if which == "ad" else cfg.sanction_list_file)
            prefix = ""
            if os.path.exists(path) and os.path.getsize(path) > 0:
                with open(path, "rb") as f:
                    f.seek(-1, os.SEEK_END)
                    if f.read(1) != b"\n":
                        prefix = "\n"
            with open(path, "a", encoding="utf-8") as f:
                f.write(prefix + name + "\n")
        info = self.reload_lists()
        info["added"] = name
        return info


def make_handler(backend, allowed_hosts):
    class Handler(BaseHTTPRequestHandler):
        server_version = "SmartDNSProxy"

        def log_message(self, *args):                                     
            pass

        def _send(self, code, payload, ctype="application/json; charset=utf-8"):
            body = payload if isinstance(payload, bytes) else json.dumps(payload).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            self.wfile.write(body)

        def _host_ok(self):
            if self.headers.get("Host", "") in allowed_hosts:
                return True
            self._send(403, {"error": "forbidden host"})
            return False

        def do_GET(self):
            if not self._host_ok():
                return
            url = urlparse(self.path)
            try:
                if url.path in ("/", "/index.html"):
                    with open(HTML_PATH, "rb") as f:
                        self._send(200, f.read(), "text/html; charset=utf-8")
                elif url.path == "/api/state":
                    self._send(200, backend.state())
                elif url.path == "/api/history":
                    self._send(200, {"items": list(backend.history)[-60:]})
                elif url.path == "/api/lists":
                    self._send(200, backend.lists())
                elif url.path == "/api/settings":
                    self._send(200, backend.get_settings())
                elif url.path == "/api/log":
                    since = int(parse_qs(url.query).get("since", ["0"])[0])
                    self._send(200, backend.log_since(max(0, since)))
                else:
                    self._send(404, {"error": "not found"})
            except FileNotFoundError:
                self._send(500, {"error": "dashboard.html is missing next to dns_proxy_web.py"})
            except Exception as exc:
                self._send(500, {"error": str(exc)})

        def do_POST(self):
            if not self._host_ok():
                return
            if not self.headers.get("Content-Type", "").startswith("application/json"):
                self._send(415, {"error": "JSON required"})
                return
            try:
                length = int(self.headers.get("Content-Length", "0"))
                if length > MAX_BODY:
                    self._send(413, {"error": "body too large"})
                    return
                data = json.loads(self.rfile.read(length) or b"{}")
                path = urlparse(self.path).path
                if path == "/api/resolve":
                    text = str(data.get("domain", ""))
                    if len(text) > MAX_DOMAIN_INPUT:
                        self._send(400, {"error": "input too long"})
                        return
                    self._send(200, {"result": backend.resolve(text), "stats": dict(backend.proxy.stats)})
                elif path == "/api/ping":
                    host = str(data.get("host", ""))
                    if not dp.is_ipv4(host):
                        self._send(400, {"error": "host must be an IPv4 address"})
                        return
                    self._send(200, measure_ping(host))
                elif path == "/api/reload":
                    self._send(200, backend.reload_lists())
                elif path == "/api/cache/clear":
                    backend.clear_cache()
                    self._send(200, {"ok": True})
                elif path == "/api/upstream":
                    backend.upstream_control(str(data.get("action", "")))
                    self._send(200, {"running": backend.upstream_running()})
                elif path == "/api/settings":
                    settings = data.get("settings")
                    if not isinstance(settings, dict):
                        raise ValueError("'settings' object required")
                    self._send(200, backend.apply_settings(settings, bool(data.get("save"))))
                elif path == "/api/lists/add":
                    self._send(200, backend.add_to_list(str(data.get("list", "")), str(data.get("domain", ""))))
                else:
                    self._send(404, {"error": "not found"})
            except (ValueError, json.JSONDecodeError) as exc:
                self._send(400, {"error": str(exc)})
            except OSError as exc:
                self._send(500, {"error": str(exc)})
            except Exception as exc:
                self._send(500, {"error": str(exc)})

    return Handler


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    open_browser = "--no-browser" not in sys.argv
    port = next((int(a) for a in args if a.isdigit()), 8053)

                                                                                
                                                                           
    argv = sys.argv[1:]
    explicit = bool(os.environ.get("DNSPROXY_CONFIG")) or any(
        a in ("--real", "--mock") or a.startswith("--config") for a in argv)
    real_path = dp.resolve_path("config_real.txt")
    cfg_path = real_path if (not explicit and os.path.exists(real_path)) else dp.config_path(argv)
    try:
        cfg = dp.load_config(cfg_path)
        ads = dp.load_list(cfg.ad_list_file)
        sanctions = dp.load_list(cfg.sanction_list_file)
    except dp.ConfigError as exc:
        print(f"Config error: {exc}")
        sys.exit(1)

    backend = Backend(dp.DnsProxy(cfg, ads, sanctions), cfg_path)
    server = None
    for candidate in range(port, port + 20):
        try:
            hosts = {f"127.0.0.1:{candidate}", f"localhost:{candidate}"}
            server = ThreadingHTTPServer(("127.0.0.1", candidate), make_handler(backend, hosts))
            port = candidate
            break
        except OSError:
            continue
    if server is None:
        print("No free port found.")
        sys.exit(1)

    url = f"http://127.0.0.1:{port}"
    mode = "REAL DNS" if cfg.real_dns_enabled else "MOCK upstream (local simulator)"
    print(f"Smart DNS Proxy dashboard running at {url}   (Ctrl+C to stop)", flush=True)
    print(f"Config: {os.path.basename(cfg_path)}  ->  {mode}", flush=True)
    if open_browser:
        threading.Timer(0.7, lambda: webbrowser.open(url)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping...")
    finally:
        server.server_close()
        if backend.upstream_running():
            backend.upstream.terminate()


if __name__ == "__main__":
    main()