import os, shutil, socket, struct, subprocess, sys, tempfile, threading, time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import dns_proxy as dp

ok_count, failed = 0, []


def check(name, cond, detail=""):
    global ok_count
    if cond:
        ok_count += 1
    else:
        failed.append(name)
    print(f"[{'PASS' if cond else 'FAIL'}] {name}" + ("" if cond else f"  {detail}"))


def make_cfg(**kw):
    base = dict(upstream_ip="127.0.0.1", upstream_port=5354, upstream_timeout_sec=1.0, sinkhole_ip="0.0.0.0",
                proxy_ip="192.0.2.10", local_ttl=60, ad_list_file="x", sanction_list_file="y", cache_enabled=True,
                entries_max_cache=0, real_dns_enabled=False, log_enabled=False, log_file="x.log")
    base.update(kw)
    return dp.Config(**base)


class Clock:                                                                       
    def __init__(self): self.now = 1000.0
    def __call__(self): return self.now


def proxy(upstream=None, **kw):
    p = dp.DnsProxy(make_cfg(**kw), {"ads.example.com", "both.example.com"}, {"svc.example.org", "both.example.com"})
    p.calls = []
    reply = upstream or ("OK", "198.51.100.7", 5)
    def fake(name):
        p.calls.append(name)
        return reply(name) if callable(reply) else reply
    p._query_upstream = fake
    return p


                                                                            
def part_a():
    print("\n== A: unit tests ==")
    bad = ["", " ", "a b.com", ".com", "a..com", "a.com..", "ex_ample.com", "نام.com", "a/b.com", "a.com\t", "a,b", "a:b.com"]
    good = ["a", "a.com", "a-b.c0m", "A.COM.", "1.2.3.4", "x" * 60 + ".com"]
    check("A1 invalid names rejected", not any(dp.is_valid_domain(x) for x in bad), [x for x in bad if dp.is_valid_domain(x)])
    check("A2 valid names accepted", all(dp.is_valid_domain(x) for x in good), [x for x in good if not dp.is_valid_domain(x)])
    check("A3 normalize removes ONE trailing dot", dp.normalize("A.Com.") == "a.com" and dp.normalize("a.com..") == "a.com.")
    e = {"example.com"}
    table = [("example.com", 1), ("b.example.com", 1), ("a.b.example.com", 1), ("notexample.com", 0),
             ("example.com.org", 0), ("com", 0), ("xexample.com", 0), ("example.co", 0)]
    check("A4 label-boundary matching", all(dp.matches(n, e) == bool(w) for n, w in table),
          [n for n, w in table if dp.matches(n, e) != bool(w)])
    check("A5 text reply parsing",
          dp.parse_text_reply(b"OK 1.2.3.4 9") == ("OK", "1.2.3.4", 9) and dp.parse_text_reply(b"NOT_FOUND") == dp.NOT_FOUND_REPLY
          and all(dp.parse_text_reply(x) == dp.ERROR_REPLY for x in
                  [b"", b"OK", b"OK 1.2.3 5", b"OK 1.2.3.4 x", b"OK 999.1.1.1 5", b"OK 1.2.3.4 -5", b"NOT_FOUND x", b"ERROR", b"\xff\xfe"]))

    p = proxy()
    r = p.resolve("both.example.com")
    check("A6 ad list beats sanction list", r.source == "AD_BLOCK" and not p.calls)
    check("A7 sanction answer", p.resolve("a.svc.example.org")[:3] == ("a.svc.example.org", "SANCTION", "OK") and not p.calls)
    check("A8 invalid input never reaches upstream", p.resolve("bad domain").status == "INVALID_INPUT" and not p.calls)

    clock, real = Clock(), time.monotonic
    time.monotonic = clock
    try:
        p = proxy()
        p.resolve("n.example.net"); clock.now += 4.9
        hit = p.resolve("n.example.net")
        check("A9 cache hit at 4.9 s keeps TTL >= 1", hit.source == "CACHE" and hit.ttl == 1 and len(p.calls) == 1, hit)
        clock.now += 0.2                                           
        r = p.resolve("n.example.net")
        check("A10 expired entry never used, replaced", r.source == "UPSTREAM" and len(p.calls) == 2)
        p = proxy(upstream=("OK", "1.1.1.1", 0)); p.resolve("z.example.net"); p.resolve("z.example.net")
        check("A11 TTL 0 is not cached", len(p.calls) == 2)
        p = proxy(upstream=dp.NOT_FOUND_REPLY); p.resolve("m.example.net"); p.resolve("m.example.net")
        check("A12 NOT_FOUND is not cached", len(p.calls) == 2)
        p = proxy(upstream=dp.ERROR_REPLY); r = p.resolve("e.example.net"); p.resolve("e.example.net")
        check("A13 SERVER_ERROR is not cached", r.status == "SERVER_ERROR" and len(p.calls) == 2)
        p = proxy(cache_enabled=False); p.resolve("c.example.net"); r = p.resolve("c.example.net")
        check("A14 cache off: never read or written", r.source == "UPSTREAM" and len(p.calls) == 2 and not p.cache)
        p = proxy(upstream=lambda n: ("OK", "9.9.9.9", 100), entries_max_cache=2)
        for n in ("s1.example.net", "s2.example.net", "s3.example.net"): p.resolve(n)
        check("A15 FIFO cap evicts the oldest", list(p.cache) == ["s2.example.net", "s3.example.net"], list(p.cache))
        p = proxy(upstream=lambda n: ("OK", "9.9.9.9", 3 if n == "short.example.net" else 100), entries_max_cache=2)
        p.resolve("short.example.net"); p.resolve("long.example.net"); clock.now += 5; p.resolve("new.example.net")
        check("A16 cap purges expired before evicting valid", set(p.cache) == {"long.example.net", "new.example.net"}, list(p.cache))
    finally:
        time.monotonic = real

    p = proxy()
    for n in ("ads.example.com", "svc.example.org", "n.example.net", "n.example.net", "bad name", ""):
        p.record(p.resolve(n))
    s = p.stats
    check("A17 stats: total = sum of the five counters", s["total"] == s["AD_BLOCK"] + s["SANCTION"] + s["CACHE"] + s["UPSTREAM"] + s["ERRORS"] == 6, s)

    d = tempfile.mkdtemp()
    def cfg_error(text, files=("ad.txt", "san.txt")):
        for f in files: open(os.path.join(d, f), "w").write("a.com\n")
        path = os.path.join(d, "c.txt"); open(path, "w").write(text)
        try:
            dp.load_config(path); return False
        except dp.ConfigError:
            return True
    good_cfg = "upstream_ip=1.2.3.4\nupstream_port=53\nsinkhole_ip=0.0.0.0\nproxy_ip=1.1.1.1\nad_list_file=ad.txt\nsanction_list_file=san.txt\n"
    cases = {"missing key": good_cfg.replace("proxy_ip=1.1.1.1\n", ""), "bad ip": good_cfg.replace("1.2.3.4", "1.2.3"),
             "port 0": good_cfg.replace("=53", "=0"), "port 70000": good_cfg.replace("=53", "=70000"),
             "bad bool": good_cfg + "cache_enabled=yes\n", "negative ttl": good_cfg + "local_ttl=-1\n",
             "timeout 0": good_cfg + "upstream_timeout_sec=0\n", "no equals sign": good_cfg + "oops\n"}
    check("A18 bad configs raise ConfigError", all(cfg_error(t) for t in cases.values()), [k for k, t in cases.items() if not cfg_error(t)])
    path = os.path.join(d, "ok.txt"); open(path, "w").write("# c\n\n" + good_cfg + "enabled_dns_real=true\ncache_max_entries=7\n")
    c = dp.load_config(path)
    check("A19 good config + alias key names", c.real_dns_enabled and c.entries_max_cache == 7 and c.local_ttl == 60 and c.cache_enabled)
    shutil.rmtree(d, ignore_errors=True)


                                                                                  
def dns_reply(query, kind):
    qid = query[:2]
    qend = 12
    while query[qend]: qend += 1 + query[qend]
    question = query[12:qend + 5]
    flags = {"nx": 0x8183, "servfail": 0x8182}.get(kind, 0x8180)
    a = lambda ip, ttl: b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, ttl, 4) + bytes(map(int, ip.split(".")))
    cname = b"\xc0\x0c" + struct.pack("!HHIH", 5, 1, 30, 6) + b"\x03www\xc0\x0c"                           
    answers = {"ok": [a("203.0.113.9", 120)], "cname": [cname, a("203.0.113.10", 77)], "noans": []}.get(kind, [])
    head = qid + struct.pack("!HHHHH", flags, 1, len(answers), 0, 0)
    return head + question + b"".join(answers)


class FakeDns(threading.Thread):
    def __init__(self):
        super().__init__(daemon=True)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); self.sock.bind(("127.0.0.1", 0))
        self.port, self.seen = self.sock.getsockname()[1], []
    def run(self):
        while True:
            try: data, addr = self.sock.recvfrom(512)
            except OSError: return
            name = ".".join(l.decode() for l in iter_labels(data))
            self.seen.append(name)
            kind = name.split(".")[0]
            if kind == "silent": continue
            if kind == "junk": self.sock.sendto(b"\x00", addr); continue
            if kind == "wrongid": data = bytes([data[0] ^ 1, data[1]]) + data[2:]
            self.sock.sendto(dns_reply(data, kind if kind in ("nx", "servfail", "cname", "noans") else "ok"), addr)


def iter_labels(packet):
    pos, out = 12, []
    while packet[pos]:
        out.append(packet[pos + 1:pos + 1 + packet[pos]]); pos += 1 + packet[pos]
    return out


def part_b():
    print("\n== B: real binary DNS (fake server on localhost) ==")
    srv = FakeDns(); srv.start()
    cfg = make_cfg(upstream_port=srv.port, real_dns_enabled=True, upstream_timeout_sec=0.8)
    ask = lambda n: dp.query_real_dns(n, cfg)
    check("B1 A record via compression pointer, real TTL", ask("ok.test") == ("OK", "203.0.113.9", 120))
    check("B2 CNAME in front of the A record", ask("cname.test") == ("OK", "203.0.113.10", 77))
    check("B3 NXDOMAIN -> NOT_FOUND", ask("nx.test") == dp.NOT_FOUND_REPLY)
    check("B4 NOERROR without A -> NOT_FOUND", ask("noans.test") == dp.NOT_FOUND_REPLY)
    check("B5 SERVFAIL -> SERVER_ERROR", ask("servfail.test") == dp.ERROR_REPLY)
    check("B6 garbage packet -> SERVER_ERROR", ask("junk.test") == dp.ERROR_REPLY)
    check("B7 wrong transaction id is ignored", ask("wrongid.test") == dp.ERROR_REPLY)
    t = time.time(); r = ask("silent.test")
    check("B8 timeout -> SERVER_ERROR after about the timeout", r == dp.ERROR_REPLY and 0.7 <= time.time() - t < 1.6, f"{time.time() - t:.2f}s")
    check("B9 a label over 63 chars never crashes", ask("a" * 64 + ".com") == dp.ERROR_REPLY)
    q = dp.build_dns_query("Example.com")[1]
    check("B10 query packet: RD flag, 1 question, QTYPE=A", struct.unpack("!HH", q[2:6]) == (0x0100, 1) and q[-4:] == b"\x00\x01\x00\x01")
    p = dp.DnsProxy(cfg, set(), set())
    first, second = p.resolve("ok.test"), p.resolve("ok.test")
    check("B11 real TTL is cached, second answer from CACHE", first.source == "UPSTREAM" and second.source == "CACHE"
          and 119 <= second.ttl <= 120 and srv.seen.count("ok.test") == 2)
    srv.sock.close()


                                                                                       
def run_cli(inputs, extra_cfg="", files=None, stdin_text=None):
    d = tempfile.mkdtemp(prefix="dnsx_")
    for f in ("dns_proxy.py", "upstream.py", "ad_list.txt", "sanction_list.txt", "config.txt"):
        shutil.copy(os.path.join(HERE, f), d)
    for name, text in (files or {}).items(): open(os.path.join(d, name), "w").write(text)
    if extra_cfg: open(os.path.join(d, "config.txt"), "a").write("\n" + extra_cfg + "\n")
    text = stdin_text if stdin_text is not None else "\n".join(inputs) + "\n"
    r = subprocess.run([sys.executable, "dns_proxy.py"], cwd=d, input=text, capture_output=True, text=True, timeout=20)
    return r, d


def part_c():
    print("\n== C: console program ==")
    r, d = run_cli(["ads.example.com", "service.example.org", "bad domain", "STATS", "Cache", "exit"], "log_file=run.log")
    check("C1 commands are case-insensitive", "Total: 3 | AD_BLOCK: 1 | SANCTION: 1 | CACHE: 0 | UPSTREAM: 0 | ERRORS: 1" in r.stdout
          and "Cache is empty." in r.stdout, r.stdout[-300:])
    log = open(os.path.join(d, "run.log")).read().splitlines()
    check("C2 log: one line per request, none for commands", len(log) == 3 and log[0].split(" | ")[1:] == ["ads.example.com", "AD_BLOCK", "OK", "0.0.0.0", "60"], log)
    check("C3 log line has timestamp and invalid input format", log[2].split(" | ")[1:] == ["bad domain", "NONE", "INVALID_INPUT", "-", "-"]
          and len(log[0].split(" | ")[0]) == 19)
    shutil.rmtree(d, ignore_errors=True)

    r, d = run_cli(["ads.example.com"], stdin_text="ads.example.com\n")
    check("C4 EOF without 'exit' ends cleanly (exit code 0)", r.returncode == 0 and "Bye." in r.stdout and "Traceback" not in r.stderr)
    shutil.rmtree(d, ignore_errors=True)

    r, d = run_cli(["x", "reload", "newad.example.com", "exit"], files={"ad_list.txt": "ads.example.com\n"})
                                                                                                             
    check("C5 reload prints the confirmation", "Lists reloaded." in r.stdout)
    shutil.rmtree(d, ignore_errors=True)

    r, d = run_cli(["ads.example.com", "exit"], files={"ad_list.txt": "ads.example.com\nbad line here\n# c\n\n  spaced.example.com  \n"})
    check("C6 bad list line warns and the program continues",
          "Warning: bad line in ad_list.txt: bad line here" in r.stdout and "AD_BLOCK" in r.stdout and r.returncode == 0)
    shutil.rmtree(d, ignore_errors=True)

    r, d = run_cli(["exit"], files={"config.txt": "upstream_ip=127.0.0.1\n"})
    check("C7 missing keys -> 'Config error:' and exit code 1", r.returncode == 1 and r.stdout.startswith("Config error:"), r.stdout)
    shutil.rmtree(d, ignore_errors=True)

    r, d = run_cli(["exit"], extra_cfg="ad_list_file=does_not_exist.txt")
    check("C8 missing list file -> 'Config error:' and exit code 1", r.returncode == 1 and "Config error:" in r.stdout)
    shutil.rmtree(d, ignore_errors=True)

    r, d = run_cli(["a..b", ".x.com", "ex ample.com", "", "  ", "ADS.example.com.", "exit"])
    blocks = r.stdout.count("Domain :")
    check("C9 every non-command input prints exactly one 5-line block", blocks == 6 and r.stdout.count("INVALID_INPUT") == 5 and r.returncode == 0, r.stdout[-200:])
    shutil.rmtree(d, ignore_errors=True)


                                                                                         
def part_d():
    print("\n== D: dashboard settings backend ==")
    try:
        import dns_proxy_web as web
    except Exception as exc:
        check("D0 dns_proxy_web imports", False, exc); return
    d = tempfile.mkdtemp(prefix="dnsweb_")
    for f in ("ad_list.txt", "sanction_list.txt", "ad_list_real.txt", "sanction_list_real.txt"):
        shutil.copy(os.path.join(HERE, f), d)
    cfg_path = os.path.join(d, "cfg.txt")
    open(cfg_path, "w").write("# my comment\nupstream_ip=127.0.0.1\nupstream_port=5354\nsinkhole_ip=0.0.0.0\nproxy_ip=192.0.2.10\n"
                              "ad_list_file=ad_list.txt\nsanction_list_file=sanction_list.txt\n# entries_max_cache=5\n")
    old_base = dp.BASE_DIR; dp.BASE_DIR = d                                                                   
    try:
        cfg = dp.load_config(cfg_path)
        be = web.Backend(dp.DnsProxy(cfg, dp.load_list(cfg.ad_list_file), dp.load_list(cfg.sanction_list_file)), cfg_path)
        bad = [{"upstream_ip": "300.1.1.1"}, {"upstream_port": "0"}, {"upstream_port": "abc"}, {"upstream_timeout_sec": "-1"},
               {"local_ttl": "-3"}, {"proxy_ip": ""}, {"ad_list_file": "missing.txt"}, {"cache_enabled": "maybe"}]
        rejected = 0
        for s in bad:
            try: be.apply_settings(s)
            except ValueError: rejected += 1
        check("D1 every bad value is rejected", rejected == len(bad), f"{rejected}/{len(bad)}")
        check("D2 nothing changed after rejected input", be.get_settings()["upstream_ip"] == "127.0.0.1" and be.proxy.cfg == cfg)
        be.proxy.cache["x.example.net"] = ("1.1.1.1", 99, time.monotonic())
        res = be.apply_settings({"real_dns_enabled": True, "upstream_ip": "8.8.8.8", "upstream_port": "53",
                                 "ad_list_file": "ad_list_real.txt", "sanction_list_file": "sanction_list_real.txt", "entries_max_cache": "50"}, save=True)
        s = res["settings"]
        check("D3 valid settings apply instantly", s["real_dns_enabled"] and s["upstream_ip"] == "8.8.8.8" and s["entries_max_cache"] == 50)
        check("D4 changing the server clears the cache", not be.proxy.cache)
        check("D5 new list files are loaded", "doubleclick.net" in be.proxy.ad_list)
        text = open(cfg_path).read()
        check("D6 save keeps comments and writes values", "# my comment" in text and "upstream_ip=8.8.8.8" in text
              and "real_dns_enabled=true" in text and "entries_max_cache=50" in text and "# entries_max_cache=5" in text, text)
        again = dp.load_config(cfg_path)
        check("D7 the saved file loads back with the same values", again.upstream_ip == "8.8.8.8" and again.real_dns_enabled and again.entries_max_cache == 50)
        if be.upstream_running(): be.upstream_control("stop")
    finally:
        dp.BASE_DIR = old_base
        shutil.rmtree(d, ignore_errors=True)


def main():
    for part in (part_a, part_b, part_c, part_d):
        part()
    print(f"\n{ok_count}/{ok_count + len(failed)} checks passed" + (f" - FAILED: {failed}" if failed else " - all OK"))
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
