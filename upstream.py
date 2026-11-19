import socket
import sys

HOST = "127.0.0.1"
PORT = 5354
MISSING_DOMAIN = "missing.example.net"
OK_REPLY = "OK 198.51.100.7 5"
NOT_FOUND_REPLY = "NOT_FOUND"


def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    try:
        sock.bind((HOST, PORT))
    except OSError as exc:
        print(f"Cannot listen on {HOST}:{PORT}: {exc}")
        sys.exit(1)

    print(f"Upstream mock listening on {HOST}:{PORT} (Ctrl+C to stop)", flush=True)

    counter = 0

    while True:
        try:
            data, addr = sock.recvfrom(4096)
        except KeyboardInterrupt:
            print("\nStopped.")
            break
        except OSError:
            continue

        parts = data.decode("utf-8", "replace").split()

        if len(parts) == 2 and parts[0] == "QUERY":
            domain = parts[1]
            counter += 1

            name = domain.lower()
            name = name[:-1] if name.endswith(".") else name

            reply = NOT_FOUND_REPLY if name == MISSING_DOMAIN else OK_REPLY

            print(f"Request #{counter}: {domain} -> {reply}", flush=True)
        else:
            reply = "ERROR malformed request"
            print(f"Ignored malformed request: {parts}", flush=True)

        try:
            sock.sendto(reply.encode("utf-8"), addr)
        except OSError:
            pass


if __name__ == "__main__":
    main()
