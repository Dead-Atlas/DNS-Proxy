# DNS Proxy

A configurable DNS proxy implemented in Python. The project supports a simulated UDP upstream server, real DNS resolution, domain filtering, response caching, query logging, automated tests, and a local web dashboard.

## Author

- **Name:** Erfan Rahmat
- **Student ID:** 4033613033
- **Team:** Individual project

All project components were designed, implemented, tested, and documented by the author.

## Features

- DNS proxy with configurable upstream server
- UDP communication with the simulated upstream server
- Real DNS resolution using DNS packets over UDP
- Advertisement and sanction domain filtering
- Configurable local sinkhole responses
- Response caching with TTL expiration
- Optional cache capacity limit using FIFO eviction
- Interactive command-line interface
- Query statistics and optional logging
- Runtime configuration and domain-list reloading
- Web dashboard for monitoring and managing the proxy
- Automated test suites

## Requirements

- Python 3
- No third-party Python packages are required for the core project.

## Project Files

| File | Description |
|---|---|
| `dns_proxy.py` | Main DNS proxy implementation |
| `upstream.py` | Simulated UDP upstream server |
| `dns_proxy_web.py` | Web dashboard backend |
| `dashboard.html` | Dashboard frontend |
| `config.txt` | Sample configuration for simulated DNS |
| `config_real.txt` | Sample configuration for real DNS |
| `ad_list.txt` | Advertisement domain list |
| `sanction_list.txt` | Sanction domain list |
| `ad_list_real.txt` | Advertisement domain list for real DNS mode |
| `sanction_list_real.txt` | Sanction domain list for real DNS mode |
| `run_tests.py` | Main test suite (T1–T13) |
| `run_extra_tests.py` | Additional validation tests |
| `test_results.txt` | Recorded output of the main test suite |

## Configuration

The project uses key-value configuration files.

The default configuration is `config.txt`. It specifies the simulated upstream server:

```text
upstream_ip=127.0.0.1
upstream_port=5354
upstream_timeout_sec=2
sinkhole_ip=0.0.0.0
proxy_ip=192.0.2.10
local_ttl=60
ad_list_file=ad_list.txt
sanction_list_file=sanction_list.txt
cache_enabled=true
```

For real DNS resolution, use `config_real.txt`. It enables real DNS mode and configures a public upstream DNS server.

Configuration values can be adjusted before starting the application.

## Domain List Format

Each domain list contains one domain per line.

Example:

```text
ads.example.com
tracker.example.net
analytics.example.org
```

Blank lines and lines beginning with `#` are ignored.

## Running the Project

### 1. Simulated DNS Mode — Command Line

Open two terminal windows.

**Terminal 1 — Start the simulated upstream server:**

```bash
python3 upstream.py
```

**Terminal 2 — Start the DNS proxy:**

```bash
python3 dns_proxy.py
```

Enter a domain when prompted.

Available interactive commands:

- `stats` — Display query statistics.
- `reload` — Reload domain lists.
- `cache` — Display cache entries.
- `exit` — Exit the application.

### 2. Real DNS Mode — Command Line

Run:

```bash
python3 dns_proxy.py --real
```

Enter a domain to resolve it through the configured real DNS upstream.

### 3. Web Dashboard

Start the dashboard in simulated mode:

```bash
python3 dns_proxy_web.py --mock
```

Or start it in real DNS mode:

```bash
python3 dns_proxy_web.py --real
```

To prevent automatic browser launching:

```bash
python3 dns_proxy_web.py --real --no-browser
```

The dashboard runs locally, starting at port `8053` or the next available port.

Open the local address printed by the application in your browser.

The dashboard provides access to DNS resolution, query history, cache information, domain lists, configuration settings, upstream status, and other management operations.

## Testing

Run the main test suite:

```bash
python3 run_tests.py
```

The test suite covers the required T1–T13 scenarios and saves its console output to `test_results.txt`.

Run additional validation tests:

```bash
python3 run_extra_tests.py
```

These tests cover additional validation, caching, DNS packet parsing, error handling, command-line behavior, and configuration management.

## Implementation Notes and Limitations

- The simulated upstream server uses UDP sockets and a text-based request/response protocol.
- Real DNS resolution uses DNS packets over UDP.
- The implementation focuses on IPv4 A-record resolution.
- DNS-over-TCP and IPv6 AAAA-record resolution are not implemented.
- The web dashboard is bound to the local machine and is not intended to be exposed directly to a public network.
- Real DNS resolution depends on network connectivity and the availability of the configured upstream server.
- Cached responses are subject to TTL expiration and cache configuration.

## Author Contribution

**Erfan Rahmat — 4033613033**

This was an individual project. All tasks were completed independently, including:

- Project design and architecture
- DNS proxy implementation
- UDP upstream simulator
- Real DNS packet construction and response parsing
- Domain filtering and configuration management
- Cache implementation and management
- Command-line interface
- Web dashboard backend and frontend
- Automated testing and validation
- Documentation