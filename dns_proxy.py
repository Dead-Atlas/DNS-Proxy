import os
import re
import sys
import socket
from dataclasses import dataclass

_DOMAIN_CHARS = re.compile(r"[A-Za-z0-9.\-]+")
_IPV4 = re.compile(r"\d{1,3}(\.\d{1,3}){3}", re.ASCII)


def is_valid_domain(text):
    if not text or not _DOMAIN_CHARS.fullmatch(text):
        return False
    return not text.startswith(".") and ".." not in text


def normalize(name):
    name = name.lower()
    return name[:-1] if name.endswith(".") else name


def is_ipv4(text):
    return bool(_IPV4.fullmatch(text)) and all(
        int(part) <= 255 for part in text.split(".")
    )


def matches(name, entries):
    labels = name.split(".")
    return any(
        ".".join(labels[i:]) in entries
        for i in range(len(labels))
    )


def fmt(value):
    return "-" if value is None else str(value)


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_FILENAME = "config.txt"

_UINT = re.compile(r"[0-9]+")
_UFLOAT = re.compile(r"[0-9]+(\.[0-9]+)?")


class ConfigError(Exception):
    pass


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
