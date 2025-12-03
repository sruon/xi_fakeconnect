#!/usr/bin/env python3
"""Fake xi_connect server - accepts any login, returns fake character."""

import hashlib, json, os, random, socket, ssl, struct, threading
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

def md5(data): return hashlib.md5(data).digest()
def pad(s, n): return s.encode()[:n-1].ljust(n, b'\x00')
def ip_bytes(ip): return bytes(map(int, ip.split('.')))

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
    # GrapIDTbl: face, head, body, hands, legs, feet, main, sub
    r = lambda: random.randint(1, 300)
    data += struct.pack('<8H', face, r(), r(), r(), r(), r(), r(), 0)
    data += struct.pack('<BB', c["zone"] & 0xFF, min(c["level"], 255))
    data += struct.pack('<BBHBB4B4H', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
    data += struct.pack('<II16BII4BII4B', 0, 0, c["level"], *([0]*15), 0, 100000, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
    return data

def char_info(idx):
    c = CFG
    cid = c["char_id"] + idx
    data = struct.pack('<IHHHH', cid, cid & 0xFFFF, 0x20, 1, 0)
    data += pad(c["char_name"], 16) + pad(c["server_name"], 16) + char_make()
    return data

def xiloader_charlist():
    n = CFG["num_chars"]
    r = bytearray(0x148)
    r[0], r[1] = 0x03, n
    for i in range(n):
        cid = CFG["char_id"] + i
        struct.pack_into('<IHBB', r, 16 + i*8, cid, cid & 0xFFFF, 0, (cid >> 16) & 0xFF)
    return bytes(r)

def next_login():
    c, ip = CFG, ip_bytes(CFG["zone_ip"])
    payload = struct.pack('<II', c["char_id"], c["char_id"]) + pad(c["char_name"], 16)
    payload += struct.pack('<I', 0) + ip + struct.pack('<I', c["zone_port"])
    payload += ip + struct.pack('<I', 54302)
    return packet(0x0B, payload)

def create_ssl_ctx():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    cert_path, key_path = f"{script_dir}/login.cert", f"{script_dir}/login.key"

    if not (os.path.exists(cert_path) and os.path.exists(key_path)):
        print("[SSL] Generating certs...")
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
        print(f"[AUTH] {ip} {req.get('username')}")
        with lock:
            sessions[ip] = {"hash": md5(f"{os.getpid()}{addr}".encode()), "data": None, "view": None}
        conn.sendall(json.dumps({"result": 1, "account_id": CFG["account_id"], "session_hash": list(sessions[ip]["hash"])}).encode())
    except Exception as e:
        print(f"[AUTH] {ip} error: {e}")
    finally:
        conn.close()

def send_charlist_to_view(ip):
    s = sessions.get(ip)
    if s and s["view"]:
        n = CFG["num_chars"]
        payload = struct.pack('<I', n) + b''.join(char_info(i) for i in range(n))
        s["view"].sendall(packet(0x20, payload))
        return True
    return False

def handle_data(conn, addr):
    ip = addr[0]
    print(f"[DATA] {ip}")
    with lock:
        if ip in sessions: sessions[ip]["data"] = conn
    try:
        while data := conn.recv(4096):
            code = data[0]
            if code == 0x01:
                with lock: send_charlist_to_view(ip)
            elif code == 0xA1:
                conn.sendall(xiloader_charlist())
                with lock:
                    if not send_charlist_to_view(ip):
                        print(f"[DATA] {ip} VIEW not ready")
            elif code == 0xA2:
                with lock:
                    s = sessions.get(ip)
                    if s and s["view"]:
                        s["view"].sendall(next_login())
                        s["view"].close()
    except: pass
    finally: conn.close()

def handle_view(conn, addr):
    ip = addr[0]
    print(f"[VIEW] {ip}")
    with lock:
        if ip in sessions: sessions[ip]["view"] = conn
    try:
        while data := conn.recv(4096):
            if len(data) < 9: continue
            code = data[8]
            if code == 0x26:
                conn.sendall(packet(0x05, struct.pack('<III', 0xAD5DE04F, 0x07FF, 0)))
            elif code == 0x24:
                conn.sendall(packet(0x23, struct.pack('<II', 1, 0x20) + pad(CFG["server_name"], 16)))
            elif code == 0x1F:
                with lock:
                    s = sessions.get(ip)
                    if s and s["data"]: s["data"].sendall(b'\x01\x00\x00\x00\x00')
            elif code == 0x07:
                with lock:
                    s = sessions.get(ip)
                    if s and s["data"]: s["data"].sendall(b'\x02\x00\x00\x00\x00')
    except: pass
    finally: conn.close()

def serve(port, handler, ssl_ctx):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(('0.0.0.0', port))
    sock.listen(5)
    if ssl_ctx: sock = ssl_ctx.wrap_socket(sock, server_side=True)
    print(f"[*] :{port}{' (SSL)' if ssl_ctx else ''}")
    while True:
        conn, addr = sock.accept()
        threading.Thread(target=handler, args=(conn, addr), daemon=True).start()

if __name__ == "__main__":
    print(f"xi_connect: {CFG['char_name']}@{CFG['server_name']}")
    ctx = create_ssl_ctx()
    for port, handler, use_ssl in [(54231, handle_auth, True), (54230, handle_data, False), (54001, handle_view, False)]:
        threading.Thread(target=serve, args=(port, handler, ctx if use_ssl else None), daemon=True).start()
    try: threading.Event().wait()
    except KeyboardInterrupt: print("bye")
