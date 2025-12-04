#!/usr/bin/env python3
"""Fake xi_connect server - accepts any login, returns fake character."""

import hashlib, json, logging, os, random, socket, ssl, struct, sys, threading, time
from datetime import datetime, timedelta, timezone
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

CFG = {
    "account_id": 1001,
    "char_id": 1,
    "char_name": "CaptureReplay",
    "server_name": "Memoria",
    "zone_ip": "127.0.0.1",
    "zone_port": 54230,
    "level": 99,
    "zone": 131,
    "nation": 0,
    "num_chars": 16,
}

sessions, lock = {}, threading.Lock()

class JsonFormatter(logging.Formatter):
    def format(self, record):
        log_obj = {
            "ts": datetime.utcnow().isoformat() + "Z",
            "level": record.levelname,
            "handler": getattr(record, "handler", "system"),
            "ip": getattr(record, "ip", None),
            "event": record.getMessage(),
        }
        if hasattr(record, "direction"):
            log_obj["direction"] = record.direction
        if hasattr(record, "cmd"):
            log_obj["cmd"] = record.cmd
        if hasattr(record, "size"):
            log_obj["size"] = record.size
        if hasattr(record, "hex"):
            log_obj["hex"] = record.hex
        return json.dumps(log_obj)

def setup_logging():
    logger = logging.getLogger("xi_connect")
    level = logging.DEBUG if os.environ.get("DEBUG", "0") == "1" else logging.INFO
    logger.setLevel(level)
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter())
    logger.addHandler(handler)
    return logger

log = setup_logging()

def log_packet(handler, ip, direction, cmd=None, data=None, msg=None):
    extra = {"handler": handler, "ip": ip, "direction": direction}
    if cmd is not None:
        extra["cmd"] = f"0x{cmd:02X}" if isinstance(cmd, int) else cmd
    if data is not None:
        extra["size"] = len(data)
        extra["hex"] = data[:64].hex() + ("..." if len(data) > 64 else "")
    log.debug(msg or f"{direction} packet", extra=extra)

def md5(data): return hashlib.md5(data).digest()
def pad(s, n): return s.encode()[:n-1].ljust(n, b'\x00')
def ip_to_uint32(ip):
    parts = list(map(int, ip.split('.')))
    return parts[0] | (parts[1] << 8) | (parts[2] << 16) | (parts[3] << 24)

def packet(cmd, payload=b""):
    pkt = bytearray(28 + len(payload))
    struct.pack_into('<I', pkt, 0, len(pkt))
    pkt[4:8] = b'IXFF'
    struct.pack_into('<I', pkt, 8, cmd)
    pkt[28:] = payload
    pkt[12:28] = md5(bytes(pkt))
    return bytes(pkt)

def char_make():
    c, race, job, face = CFG, random.randint(1, 8), random.randint(1, 14), random.randint(1, 8)
    data = struct.pack('<HBBHBBBBH', race, job, 0, face, c["nation"], 0, 1, 1, 1)
    r = lambda: random.randint(1, 300)
    data += struct.pack('<8H', face, r(), r(), r(), r(), r(), r(), 0)
    data += struct.pack('<BB', c["zone"] & 0xFF, min(c["level"], 255))
    data += struct.pack('<BBHBB4B4H', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
    data += struct.pack('<II16BII4BII4B', 0, 0, c["level"], *([0]*15), 0, 100000, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
    return data

def char_info(idx):
    c = CFG
    cid = c["char_id"] + idx
    data = struct.pack('<III', cid, cid, 1)
    data += pad(c["char_name"], 16) + pad(c["server_name"], 16) + char_make()
    return data

def xiloader_charlist():
    n = CFG["num_chars"]
    r = bytearray(0x148)
    r[0], r[1] = 0x03, n
    for i in range(n):
        cid = CFG["char_id"] + i
        offset = 16 * (i + 1)
        struct.pack_into('<II', r, offset, cid, cid)
    return bytes(r)

def next_login(char_id):
    c = CFG
    zone_ip = ip_to_uint32(c["zone_ip"])
    payload = struct.pack('<II', char_id, char_id & 0xFFFF) + pad(c["char_name"], 16)
    payload += struct.pack('<I', (char_id >> 16) & 0xFF)
    payload += struct.pack('<II', zone_ip, c["zone_port"])
    payload += struct.pack('<II', zone_ip, 54302)
    return packet(0x0B, payload)

def create_ssl_ctx():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    cert_path, key_path = f"{script_dir}/login.cert", f"{script_dir}/login.key"

    if not (os.path.exists(cert_path) and os.path.exists(key_path)):
        log.info("Generating SSL certs", extra={"handler": "ssl", "ip": None})
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cert = (x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")]))
            .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")]))
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.now(timezone.utc))
            .not_valid_after(datetime.now(timezone.utc) + timedelta(days=3650))
            .sign(key, hashes.SHA256()))
        with open(cert_path, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
        with open(key_path, "wb") as f:
            f.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()))

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1
    ctx.set_ciphers('DEFAULT:@SECLEVEL=0')
    ctx.load_cert_chain(cert_path, key_path)
    return ctx

def handle_auth(conn, addr):
    ip = addr[0]
    try:
        data = conn.recv(4096)
        if not data: return
        req = json.loads(data)
        log.info(f"login user={req.get('username')}", extra={"handler": "auth", "ip": ip, "direction": "in"})
        with lock:
            sessions[ip] = {"hash": md5(f"{os.getpid()}{addr}".encode()), "data": None, "view": None}
        resp = json.dumps({"result": 1, "account_id": CFG["account_id"], "session_hash": list(sessions[ip]["hash"])}).encode()
        conn.sendall(resp)
        log.info("login success", extra={"handler": "auth", "ip": ip, "direction": "out"})
    except Exception as e:
        log.error(f"error: {e}", extra={"handler": "auth", "ip": ip})
    finally:
        conn.close()

def send_charlist_to_view(ip):
    s = sessions.get(ip)
    if s and s["view"]:
        n = CFG["num_chars"]
        payload = struct.pack('<I', n) + b''.join(char_info(i) for i in range(n))
        pkt = packet(0x20, payload)
        log_packet("view", ip, "out", 0x20, pkt, "charlist")
        s["view"].sendall(pkt)
        return True
    return False

def handle_data(conn, addr):
    ip = addr[0]
    log.info("connected", extra={"handler": "data", "ip": ip})
    with lock:
        if ip in sessions: sessions[ip]["data"] = conn
    try:
        while data := conn.recv(4096):
            code = data[0]
            log_packet("data", ip, "in", code, data)
            if code == 0xFE:
                pass  # real server sends nothing
            elif code == 0x01:
                with lock: send_charlist_to_view(ip)
            elif code == 0xA1:
                resp = xiloader_charlist()
                log_packet("data", ip, "out", 0xA1, resp, "xiloader_charlist")
                conn.sendall(resp)
                with lock:
                    if not send_charlist_to_view(ip):
                        log.warning("VIEW not ready", extra={"handler": "data", "ip": ip})
            elif code == 0xA2:
                with lock:
                    s = sessions.get(ip)
                    if s and s["view"]:
                        char_id = s.get("selected_char", CFG["char_id"])
                        pkt = next_login(char_id)
                        log_packet("data", ip, "out", 0x0B, pkt, f"next_login char_id={char_id}")
                        view_sock = s["view"]
                        s["view"] = None
                        view_sock.sendall(pkt)
                        time.sleep(0.1)
                        try:
                            view_sock.shutdown(socket.SHUT_RDWR)
                        except:
                            pass
                        view_sock.close()
    except Exception as e:
        log.error(f"error: {e}", extra={"handler": "data", "ip": ip})
    finally: conn.close()

def handle_view(conn, addr):
    ip = addr[0]
    log.info("connected", extra={"handler": "view", "ip": ip})
    with lock:
        if ip in sessions: sessions[ip]["view"] = conn
    try:
        while True:
            with lock:
                s = sessions.get(ip)
                if s and s["view"] is None:
                    break
            data = conn.recv(4096)
            if not data:
                break
            if len(data) < 9: continue
            code = data[8]
            log_packet("view", ip, "in", code, data)
            if code == 0x26:
                resp = packet(0x05, struct.pack('<III', 0xAD5DE04F, 0x0FFF, 0x00FC))
                log_packet("view", ip, "out", 0x05, resp, "version")
                conn.sendall(resp)
            elif code == 0x24:
                resp = packet(0x23, struct.pack('<II', 1, 0x20) + pad(CFG["server_name"], 16))
                log_packet("view", ip, "out", 0x23, resp, "worldlist")
                conn.sendall(resp)
            elif code == 0x1F:
                with lock:
                    s = sessions.get(ip)
                    if s and s["data"]:
                        log.info("trigger charlist", extra={"handler": "view", "ip": ip, "direction": "out"})
                        s["data"].sendall(b'\x01\x00\x00\x00\x00')
            elif code == 0x07:
                char_id = struct.unpack('<I', data[28:32])[0]
                log.info(f"selected char_id={char_id}", extra={"handler": "view", "ip": ip})
                with lock:
                    s = sessions.get(ip)
                    if s:
                        s["selected_char"] = char_id
                        if s["data"]:
                            s["data"].sendall(b'\x02\x00\x00\x00\x00')
    except Exception as e:
        log.error(f"error: {e}", extra={"handler": "view", "ip": ip})
    finally: conn.close()

def serve(port, handler, ssl_ctx):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(('0.0.0.0', port))
    sock.listen(5)
    if ssl_ctx: sock = ssl_ctx.wrap_socket(sock, server_side=True)
    log.info(f"listening on :{port}" + (" (SSL)" if ssl_ctx else ""), extra={"handler": "system", "ip": None})
    while True:
        conn, addr = sock.accept()
        threading.Thread(target=handler, args=(conn, addr), daemon=True).start()

if __name__ == "__main__":
    log.info(f"starting {CFG['char_name']}@{CFG['server_name']}", extra={"handler": "system", "ip": None})
    use_tls = os.environ.get("DISABLE_TLS", "0") != "1"
    ctx = create_ssl_ctx() if use_tls else None
    for port, handler, use_ssl in [(54231, handle_auth, use_tls), (54230, handle_data, False), (54001, handle_view, False)]:
        threading.Thread(target=serve, args=(port, handler, ctx if use_ssl else None), daemon=True).start()
    log.info(f"TLS {'enabled' if use_tls else 'disabled'}", extra={"handler": "system", "ip": None})
    try: threading.Event().wait()
    except KeyboardInterrupt: log.info("shutdown", extra={"handler": "system", "ip": None})
