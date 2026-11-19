import os
import random
import re
import socket
import struct
import sys
import time
from collections import namedtuple
from dataclasses import dataclass
from datetime import datetime

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_FILENAME = "config.txt"
PROMPT = "Enter domain (or exit): "

Result = namedtuple("Result", ["domain", "source", "status", "ip", "ttl"])


class ConfigError(Exception):
    pass


_DOMAIN_CHARS = re.compile(r"[A-Za-z0-9.\-]+")
_IPV4 = re.compile(r"\d{1,3}(\.\d{1,3}){3}", re.ASCII)
_UINT = re.compile(r"[0-9]+")
_UFLOAT = re.compile(r"[0-9]+(\.[0-9]+)?")


def is_valid_domain(text):
    if not text or not _DOMAIN_CHARS.fullmatch(text):
        return False
    return not text.startswith(".") and ".." not in text


def normalize(name):
    name = name.lower()
    return name[:-1] if name.endswith(".") else name


def is_ipv4(text):
    return bool(_IPV4.fullmatch(text)) and all(int(p) <= 255 for p in text.split("."))


def matches(name, entries):
    labels = name.split(".")
    return any(".".join(labels[i:]) in entries for i in range(len(labels)))


def fmt(value):
    return "-" if value is None else str(value)


@dataclass
class Config:
    upstream_ip: str
    upstream_port: int
    upstream_timeout_sec: float
    sinkhole_ip: str
    proxy_ip: str
    local_ttl: int
    ad_list_file: str
    sanction_list_file: str
    cache_enabled: bool
    entries_max_cache: int
    real_dns_enabled: bool
    log_enabled: bool
    log_file: str


def resolve_path(path):
    return path if os.path.isabs(path) else os.path.join(BASE_DIR, path)


def config_path(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    name = os.environ.get("DNSPROXY_CONFIG") or CONFIG_FILENAME
    for i, arg in enumerate(argv):
        if arg == "--real":
            name = "config_real.txt"
        elif arg == "--config" and i + 1 < len(argv):
            name = argv[i + 1]
        elif arg.startswith("--config="):
            name = arg.split("=", 1)[1]
    return resolve_path(name)


def _read_lines(path, label):
    try:
        with open(path, encoding="utf-8-sig") as f:
            return f.read().splitlines()
    except FileNotFoundError:
        raise ConfigError(f"{label} not found: {path}")
    except (OSError, UnicodeDecodeError) as exc:
        raise ConfigError(f"cannot read {label} ({path}): {exc}")


def _pick(raw, keys, default=None, required=False):
    for key in keys:
        if key in raw:
            if raw[key] == "":
                raise ConfigError(f"empty value for '{key}'")
            return key, raw[key]
    if required:
        raise ConfigError(f"missing required key '{keys[0]}'")
    return keys[0], default


def _as_ipv4(key, value):
    if not is_ipv4(value):
        raise ConfigError(f"'{key}' must be an IPv4 address, got '{value}'")
    return value


def _as_int(key, value, lo, hi=None):
    if not _UINT.fullmatch(value) or int(value) < lo or (hi is not None and int(value) > hi):
        rng = f">= {lo}" if hi is None else f"between {lo} and {hi}"
        raise ConfigError(f"'{key}' must be an integer {rng}, got '{value}'")
    return int(value)


def _as_bool(key, value):
    if value.lower() not in ("true", "false"):
        raise ConfigError(f"'{key}' must be true or false, got '{value}'")
    return value.lower() == "true"


def load_config(path):
    raw = {}
    for number, line in enumerate(_read_lines(path, "config file"), 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            raise ConfigError(f"line {number} is not in key=value form: '{line}'")
        key, value = line.split("=", 1)
        raw[key.strip().lower()] = value.strip()

    k, v = _pick(raw, ["upstream_ip"], required=True)
    upstream_ip = _as_ipv4(k, v)
    k, v = _pick(raw, ["upstream_port"], required=True)
    upstream_port = _as_int(k, v, 1, 65535)
    k, v = _pick(raw, ["upstream_timeout_sec"], default="2")
    if not _UFLOAT.fullmatch(v) or float(v) <= 0:
        raise ConfigError(f"'{k}' must be a positive number, got '{v}'")
    timeout = float(v)
    k, v = _pick(raw, ["sinkhole_ip"], required=True)
    sinkhole_ip = _as_ipv4(k, v)
    k, v = _pick(raw, ["proxy_ip"], required=True)
    proxy_ip = _as_ipv4(k, v)
    k, v = _pick(raw, ["local_ttl"], default="60")
    local_ttl = _as_int(k, v, 0)
    _, ad_file = _pick(raw, ["ad_list_file"], required=True)
    _, sanction_file = _pick(raw, ["sanction_list_file"], required=True)
    k, v = _pick(raw, ["cache_enabled"], default="true")
    cache_enabled = _as_bool(k, v)

    k, v = _pick(raw, ["entries_max_cache", "cache_max_entries"], default="0")
    entries_max = _as_int(k, v, 0)
    k, v = _pick(raw, ["real_dns_enabled", "enabled_dns_real"], default="false")
    real_dns = _as_bool(k, v)
    k, v = _pick(raw, ["log_enabled"], default="true")
    log_enabled = _as_bool(k, v)
    _, log_file = _pick(raw, ["log_file"], default="log.txt")

    return Config(
        upstream_ip, upstream_port, timeout, sinkhole_ip, proxy_ip,
        local_ttl, ad_file, sanction_file, cache_enabled, entries_max,
        real_dns, log_enabled, log_file
    )


def load_list(file_value):
    entries = set()
    for line in _read_lines(resolve_path(file_value), "list file"):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if not is_valid_domain(line):
            print(f"Warning: bad line in {file_value}: {line}", flush=True)
            continue
        entries.add(normalize(line))
    return entries


ERROR_REPLY = ("SERVER_ERROR", None, None)
NOT_FOUND_REPLY = ("NOT_FOUND", None, None)


def parse_text_reply(data):
    try:
        parts = data.decode("utf-8").split()
    except UnicodeDecodeError:
        return ERROR_REPLY
    if parts == ["NOT_FOUND"]:
        return NOT_FOUND_REPLY
    if len(parts) == 3 and parts[0] == "OK" and is_ipv4(parts[1]) and _UINT.fullmatch(parts[2]):
        return ("OK", parts[1], int(parts[2]))
    return ERROR_REPLY


def query_text_upstream(name, cfg):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.settimeout(cfg.upstream_timeout_sec)
        sock.sendto(
            f"QUERY {name}".encode("ascii"),
            (cfg.upstream_ip, cfg.upstream_port)
        )
        data, _ = sock.recvfrom(4096)
    except OSError:
        return ERROR_REPLY
    finally:
        sock.close()
    return parse_text_reply(data)


def build_dns_query(name):
    if len(name) > 253:
        raise ValueError("name too long")
    qid = random.randint(0, 0xFFFF)
    packet = struct.pack("!HHHHHH", qid, 0x0100, 1, 0, 0, 0)
    for label in name.split("."):
        raw = label.encode("ascii")
        if not 0 < len(raw) <= 63:
            raise ValueError("bad label length")
        packet += bytes([len(raw)]) + raw
    packet += b"\x00" + struct.pack("!HH", 1, 1)
    return qid, packet


def _skip_name(data, pos):
    while True:
        if pos >= len(data):
            raise ValueError("truncated name")
        length = data[pos]
        if length == 0:
            return pos + 1
        if length & 0xC0 == 0xC0:
            return pos + 2
        if length & 0xC0:
            raise ValueError("bad label type")
        pos += 1 + length


def parse_dns_response(data, qid):
    if len(data) < 12:
        raise ValueError("short packet")
    rid, flags, qdcount, ancount, _, _ = struct.unpack("!HHHHHH", data[:12])
    if rid != qid or not flags & 0x8000:
        raise ValueError("not our response")
    rcode = flags & 0x000F
    if rcode == 3:
        return NOT_FOUND_REPLY
    if rcode != 0:
        raise ValueError(f"rcode {rcode}")
    pos = 12
    for _ in range(qdcount):
        pos = _skip_name(data, pos) + 4
    for _ in range(ancount):
        pos = _skip_name(data, pos)
        if pos + 10 > len(data):
            raise ValueError("truncated record")
        rtype, rclass, ttl, rdlen = struct.unpack("!HHIH", data[pos:pos + 10])
        pos += 10
        if pos + rdlen > len(data):
            raise ValueError("truncated rdata")
        if rtype == 1 and rclass == 1 and rdlen == 4:
            return ("OK", ".".join(str(b) for b in data[pos:pos + 4]), ttl)
        pos += rdlen
    if flags & 0x0200:
        raise ValueError("truncated response")
    return NOT_FOUND_REPLY


def query_real_dns(name, cfg):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        qid, packet = build_dns_query(name)
        target = (cfg.upstream_ip, cfg.upstream_port)
        deadline = time.monotonic() + cfg.upstream_timeout_sec
        sock.sendto(packet, target)
        while True:
            left = deadline - time.monotonic()
            if left <= 0:
                return ERROR_REPLY
            sock.settimeout(left)
            data, addr = sock.recvfrom(4096)
            if (
                addr[0] != target[0]
                or len(data) < 2
                or struct.unpack("!H", data[:2])[0] != qid
            ):
                continue
            return parse_dns_response(data, qid)
    except (OSError, ValueError, struct.error):
        return ERROR_REPLY
    finally:
        sock.close()


class DnsProxy:
    def __init__(self, cfg, ad_list, sanction_list):
        self.cfg = cfg
        self.ad_list = ad_list
        self.sanction_list = sanction_list
        self.cache = {}
        self.stats = {
            "total": 0,
            "AD_BLOCK": 0,
            "SANCTION": 0,
            "CACHE": 0,
            "UPSTREAM": 0,
            "ERRORS": 0
        }

    @staticmethod
    def _remaining(entry, now):
        _, ttl, stored_at = entry
        return ttl - int(now - stored_at)

    def _purge_expired(self):
        now = time.monotonic()
        for name in [
            n for n, e in self.cache.items()
            if self._remaining(e, now) < 1
        ]:
            del self.cache[name]

    def _cache_get(self, name):
        entry = self.cache.get(name)
        if entry is None:
            return None
        remaining = self._remaining(entry, time.monotonic())
        if remaining < 1:
            del self.cache[name]
            return None
        return entry[0], remaining

    def _cache_put(self, name, ip, ttl):
        self.cache.pop(name, None)
        limit = self.cfg.entries_max_cache
        if limit > 0 and len(self.cache) >= limit:
            self._purge_expired()
            while len(self.cache) >= limit:
                del self.cache[next(iter(self.cache))]
        self.cache[name] = (ip, ttl, time.monotonic())

    def _query_upstream(self, name):
        try:
            if self.cfg.real_dns_enabled:
                return query_real_dns(name, self.cfg)
            return query_text_upstream(name, self.cfg)
        except Exception:
            return ERROR_REPLY

    def resolve(self, raw_line):
        text = raw_line.strip()
        if not is_valid_domain(text):
            return Result(
                text if text else "(empty)",
                "NONE",
                "INVALID_INPUT",
                None,
                None
            )
        name = normalize(text)
        cfg = self.cfg
        if matches(name, self.ad_list):
            return Result(name, "AD_BLOCK", "OK", cfg.sinkhole_ip, cfg.local_ttl)
        if matches(name, self.sanction_list):
            return Result(name, "SANCTION", "OK", cfg.proxy_ip, cfg.local_ttl)
        if cfg.cache_enabled:
            hit = self._cache_get(name)
            if hit:
                return Result(name, "CACHE", "OK", hit[0], hit[1])
        status, ip, ttl = self._query_upstream(name)
        if status == "OK" and cfg.cache_enabled and ttl > 0:
            self._cache_put(name, ip, ttl)
        return Result(name, "UPSTREAM", status, ip, ttl)

    def record(self, result):
        self.stats["total"] += 1
        if result.status in ("INVALID_INPUT", "SERVER_ERROR"):
            self.stats["ERRORS"] += 1
        else:
            self.stats[result.source] += 1
        if self.cfg.log_enabled:
            stamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            line = " | ".join([
                stamp,
                result.domain,
                result.source,
                result.status,
                fmt(result.ip),
                fmt(result.ttl)
            ])
            try:
                with open(
                    resolve_path(self.cfg.log_file),
                    "a",
                    encoding="utf-8"
                ) as f:
                    f.write(line + "\n")
            except OSError:
                pass

    def show_stats(self):
        s = self.stats
        print(
            f"Total: {s['total']} | AD_BLOCK: {s['AD_BLOCK']} | "
            f"SANCTION: {s['SANCTION']} | CACHE: {s['CACHE']} | "
            f"UPSTREAM: {s['UPSTREAM']} | ERRORS: {s['ERRORS']}"
        )

    def reload_lists(self):
        try:
            ads = load_list(self.cfg.ad_list_file)
            sanctions = load_list(self.cfg.sanction_list_file)
        except ConfigError as exc:
            print(f"Reload failed: {exc}")
            return
        self.ad_list, self.sanction_list = ads, sanctions
        print("Lists reloaded.")

    def show_cache(self):
        self._purge_expired()
        if not self.cache:
            print("Cache is empty.")
            return
        now = time.monotonic()
        for name, entry in self.cache.items():
            print(f"{name} | {entry[0]} | {self._remaining(entry, now)}")


def print_block(result):
    print(f"Domain : {result.domain}")
    print(f"Source : {result.source}")
    print(f"Status : {result.status}")
    print(f"IP : {fmt(result.ip)}")
    print(f"TTL : {fmt(result.ttl)}")
    print(flush=True)


def main():
    try:
        cfg = load_config(config_path())
        ads = load_list(cfg.ad_list_file)
        sanctions = load_list(cfg.sanction_list_file)
    except ConfigError as exc:
        print(f"Config error: {exc}")
        sys.exit(1)

    proxy = DnsProxy(cfg, ads, sanctions)
    print("DNS Proxy ready.", flush=True)
    interactive = sys.stdin.isatty()

    while True:
        try:
            line = input(PROMPT)
            if not interactive:
                print(line)
            command = line.strip().lower()
            if command == "exit":
                print("Bye.")
                break
            if command == "stats":
                proxy.show_stats()
            elif command == "reload":
                proxy.reload_lists()
            elif command == "cache":
                proxy.show_cache()
            else:
                result = proxy.resolve(line)
                proxy.record(result)
                print_block(result)
        except (EOFError, KeyboardInterrupt):
            print("\nBye.")
            break


if __name__ == "__main__":
    main()