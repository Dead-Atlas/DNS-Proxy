import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
PROMPT = "Enter domain (or exit): "
FILES = ["dns_proxy.py", "upstream.py", "ad_list.txt", "sanction_list.txt", "config.txt"]


class Proc:
    def __init__(self, script, cwd):
        self.p = subprocess.Popen([sys.executable, "-u", script], cwd=cwd,
                                  stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                  stderr=subprocess.STDOUT)
        self.buf, self.pos, self.lock = "", 0, threading.Lock()
        threading.Thread(target=self._pump, daemon=True).start()

    def _pump(self):
        fd = self.p.stdout.fileno()
        while True:
            try:
                chunk = os.read(fd, 4096)
            except OSError:
                break
            if not chunk:
                break
            with self.lock:
                self.buf += chunk.decode("utf-8", "replace")

    def wait_for(self, text, timeout=15):
        end = time.time() + timeout
        while time.time() < end:
            with self.lock:
                i = self.buf.find(text, self.pos)
                if i >= 0:
                    out = self.buf[self.pos:i + len(text)]
                    self.pos = i + len(text)
                    return out
            time.sleep(0.02)
        raise TimeoutError(f"timeout waiting for {text!r}")

    def send(self, line):
        self.p.stdin.write((line + "\n").encode())
        self.p.stdin.flush()
        return self.wait_for(PROMPT)

    def lines(self, prefix):
        with self.lock:
            return [l for l in self.buf.splitlines() if l.startswith(prefix)]

    def stop(self):
        try:
            self.p.kill()
        except OSError:
            pass


def block(text):
    return {k: v.strip() for k, v in re.findall(r"^(Domain|Source|Status|IP|TTL)\s*:\s*(.*)$", text, re.M)}


results = []


def check(tid, ok, detail=""):
    results.append((tid, ok))
    print(f"[{'PASS' if ok else 'FAIL'}] {tid} {detail}")


def expect(tid, out, domain, source, status, ip, ttl):
    b = block(out)
    want = {"Domain": domain, "Source": source, "Status": status, "IP": ip, "TTL": ttl}
    ok = all(b.get(k) == v for k, v in want.items() if v is not None)
    check(tid, ok, "" if ok else f"got {b} expected {want}")
    return b


def workdir(config_changes=None):
    d = tempfile.mkdtemp(prefix="dnsproxy_")
    for f in FILES:
        shutil.copy(os.path.join(HERE, f), d)
    if config_changes:
        with open(os.path.join(d, "config.txt"), "a") as f:
            f.write("\n" + "\n".join(config_changes) + "\n")                                     
    return d


def start(d):
    up = Proc("upstream.py", d)
    up.wait_for("listening")
    px = Proc("dns_proxy.py", d)
    px.wait_for(PROMPT)
    return up, px


def main():
    transcript = []

                                                      
    d = workdir()
    up, px = start(d)
    up_count = lambda: len(up.lines("Request #"))
    time.sleep(0.2)

    expect("T1", px.send("ads.example.com"), "ads.example.com", "AD_BLOCK", "OK", "0.0.0.0", "60")
    expect("T2", px.send("sub.ads.example.com"), "sub.ads.example.com", "AD_BLOCK", "OK", "0.0.0.0", "60")
    expect("T3", px.send("ADS.Example.COM."), "ads.example.com", "AD_BLOCK", "OK", "0.0.0.0", "60")
    check("T1-T3 no upstream traffic", up_count() == 0)

    expect("T4", px.send("notads.example.com"), "notads.example.com", "UPSTREAM", "OK", "198.51.100.7", "5")
    check("T4 upstream line", up.lines("Request #") == ["Request #1: notads.example.com -> OK 198.51.100.7 5"])
    expect("T5", px.send("service.example.org"), "service.example.org", "SANCTION", "OK", "192.0.2.10", "60")
    expect("T6", px.send("both.example.com"), "both.example.com", "AD_BLOCK", "OK", "0.0.0.0", "60")
    check("T5-T6 no upstream traffic", up_count() == 1)

    t7 = time.time()
    expect("T7", px.send("normal.example.net"), "normal.example.net", "UPSTREAM", "OK", "198.51.100.7", "5")
    check("T7 upstream line", up.lines("Request #")[-1] == "Request #2: normal.example.net -> OK 198.51.100.7 5")
    time.sleep(2.0)
    b = expect("T8", px.send("normal.example.net"), "normal.example.net", "CACHE", "OK", "198.51.100.7", None)
    check("T8 TTL in 1..5", b.get("TTL", "x").isdigit() and 1 <= int(b["TTL"]) <= 5, f"TTL={b.get('TTL')}")
    check("T8 no upstream traffic", up_count() == 2)
    time.sleep(max(0, t7 + 6.2 - time.time()))
    expect("T9", px.send("normal.example.net"), "normal.example.net", "UPSTREAM", "OK", "198.51.100.7", "5")
    check("T9 upstream line", up.lines("Request #")[-1] == "Request #3: normal.example.net -> OK 198.51.100.7 5")

    for i in (1, 2):
        expect(f"T10.{i}", px.send("missing.example.net"), "missing.example.net", "UPSTREAM", "NOT_FOUND", "-", "-")
    check("T10 two upstream lines (not cached)", up_count() == 5)

    up.stop()
    time.sleep(0.3)
    start_t = time.time()
    expect("T11.1", px.send("other.example.net"), "other.example.net", "UPSTREAM", "SERVER_ERROR", "-", "-")
    waited = time.time() - start_t
    check("T11 waited about timeout (>=1.8 s)", waited >= 1.8, f"{waited:.2f}s")
    expect("T11.2", px.send("ads.example.com"), "ads.example.com", "AD_BLOCK", "OK", "0.0.0.0", "60")

    expect("T12.1", px.send(""), "(empty)", "NONE", "INVALID_INPUT", "-", "-")
    expect("T12.2", px.send("bad domain.com"), "bad domain.com", "NONE", "INVALID_INPUT", "-", "-")
    px.p.stdin.write(b"exit\n")                                                        
    px.p.stdin.flush()
    check("exit prints Bye.", bool(px.wait_for("Bye.")))
    transcript.append(("Run 1 (T1-T12)", px))
    px.stop()

                                                  
    d2 = workdir(["sinkhole_ip=10.0.0.1", "cache_enabled=false"])
    up2, px2 = start(d2)
    expect("T13.1", px2.send("ads.example.com"), "ads.example.com", "AD_BLOCK", "OK", "10.0.0.1", "60")
    for i in (2, 3):
        expect(f"T13.{i}", px2.send("normal.example.net"), "normal.example.net", "UPSTREAM", "OK", "198.51.100.7", "5")
    check("T13 two upstream lines (cache off)", len(up2.lines("Request #")) == 2)
    px2.p.stdin.write(b"exit\n")
    px2.p.stdin.flush()
    px2.wait_for("Bye.")
    transcript.append(("Run 2 (T13: sinkhole_ip=10.0.0.1, cache_enabled=false)", px2))

    with open(os.path.join(HERE, "test_results.txt"), "w", encoding="utf-8") as f:
        for title, proc in transcript:
            f.write(f"===== {title} - Proxy console =====\n{proc.buf}\n")
        f.write("===== Upstream console, run 1 =====\n" + up.buf + "\n")
        f.write("===== Upstream console, run 2 =====\n" + up2.buf + "\n")
    for p in (px, px2, up, up2):
        p.stop()
    shutil.rmtree(d, ignore_errors=True)
    shutil.rmtree(d2, ignore_errors=True)

    failed = [t for t, ok in results if not ok]
    print(f"\n{len(results) - len(failed)}/{len(results)} checks passed" +
          (f" - FAILED: {failed}" if failed else " - all OK"))
    print("Transcript saved to test_results.txt")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
