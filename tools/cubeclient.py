"""
Read-only cubeSQL client for WISO Hausverwalter's embedded server.
Clear-text AND AES-128 encrypted connect, reconstructed from the official SDK
(github.com/cubesql/sdk, C_SDK/cubesql.c + csql.h + crypt/).

Usage:
    python3 -I cubeclient.py probe
    python3 -I cubeclient.py schema
    python3 -I cubeclient.py dump OUTDIR
    python3 -I cubeclient.py sql "SELECT ..."
Defaults: 127.0.0.1:14423. Credentials via env CUBE_USER/CUBE_PASS or the list.
"""
import socket, struct, hashlib, zlib, sys, os, csv, ssl
from cubecrypto import Ctx, encrypt_buffer, decrypt_buffer

SIG = 0x53514C53
CONNECT, SELECT, EXECUTE, CLOSE, PING, CHUNK = 1, 2, 3, 7, 8, 9
CLEAR_P1, CLEAR_P2 = 20, 21
ENC_P1, ENC_P2 = 22, 23
CHUNK_OK = 25
C_COMPRESS = 0x01
S_PARTIAL = 0x20
S_COMPRESSED = 0x08
S_HAS_TABLE = 0x80
S_HAS_ROWID = 0x04
END_CHUNK = 777
ENC_NONE, ENC_AES128 = 0, 2


class CubeErr(Exception):
    def __init__(self, code, msg):
        self.code = code
        self.msg = msg
        super().__init__(f"[{code}] {msg}")


def sha1(b):
    return hashlib.sha1(b).digest()


class Cube:
    def __init__(self, host, port, timeout=20, tls=False):
        raw = socket.create_connection((host, port), timeout)
        raw.settimeout(timeout)
        if tls:
            ctx = ssl._create_unverified_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            try:
                ctx.minimum_version = ssl.TLSVersion.TLSv1
            except Exception:
                pass
            try:
                ctx.set_ciphers('DEFAULT:@SECLEVEL=0')
            except Exception:
                pass
            self.s = ctx.wrap_socket(raw, server_hostname='localhost')
        else:
            self.s = raw
        self.timeout = timeout
        self.encryption = ENC_NONE
        self.enc_ctx = None
        self.dec_ctx = None

    def _hdr(self, packetsize, nfields, command, selector, enc, flag1=C_COMPRESS):
        return struct.pack('>IIBBBBBBBBIIIHH', SIG, packetsize, command, selector,
                           flag1, 0, 0, enc, 4, 0, nfields, 0, self.timeout, 0, 0)

    def _sendn(self, b):
        self.s.sendall(b)

    def _send(self, command, selector, fields=(), enc_override=None):
        enc = self.encryption if enc_override is None else enc_override
        data = b''.join(fields)
        sizearr = b''.join(struct.pack('>i', len(f)) for f in fields)
        if enc != ENC_NONE and data:
            iv = bytearray(os.urandom(16))
            buf = bytearray(data)
            ivout, ct = encrypt_buffer(buf, len(data), bytearray(iv), self.enc_ctx)
            body = ivout + ct
            packetsize = len(data) + len(sizearr) + 16
        else:
            body = data
            packetsize = len(data) + len(sizearr)
        self._sendn(self._hdr(packetsize, len(fields), command, selector, enc))
        if sizearr:
            self._sendn(sizearr)
        if body:
            self._sendn(body)

    def _recvn(self, n):
        b = b''
        while len(b) < n:
            c = self.s.recv(n - len(b))
            if not c:
                raise CubeErr(-1, "connection closed")
            b += c
        return b

    def _recv_header(self):
        (sig, packetSize, errorCode, flag1, enc, expanded, rows, cols, numFields, r1, r2) = \
            struct.unpack('>IIHBBIIIIHH', self._recvn(32))
        if sig != SIG:
            raise CubeErr(-1, "bad signature")
        return dict(packetSize=packetSize, err=errorCode, flag1=flag1, enc=enc,
                    expanded=expanded, rows=rows, cols=cols, numFields=numFields)

    def _recv_raw(self):
        """header + raw payload, no decryption (used during handshake)."""
        h = self._recv_header()
        payload = self._recvn(h['packetSize']) if h['packetSize'] else b''
        return h, payload

    def _recv_reply(self):
        h = self._recv_header()
        payload = self._recvn(h['packetSize']) if h['packetSize'] else b''
        if h['enc'] != ENC_NONE and payload:
            buf = bytearray(payload)
            plen = decrypt_buffer(buf, len(payload), self.dec_ctx)
            payload = bytes(buf[:plen])
        if h['err'] not in (0, END_CHUNK):
            raise CubeErr(h['err'], payload.decode('utf-8', 'replace'))
        if h['flag1'] & S_COMPRESSED and payload:
            payload = zlib.decompress(payload)
        return h, payload

    # ---- connect ----
    def connect_clear(self, user, password, hh=None):
        """password may be None if hh (=SHA1(SHA1(password))) is supplied directly."""
        self._send(CONNECT, CLEAR_P1, [hashlib.sha1(user.encode()).hexdigest().encode() + b'\x00'],
                   enc_override=ENC_NONE)
        _, pool = self._recv_raw()
        if len(pool) < 20:
            raise CubeErr(-1, f"bad randpool {len(pool)}")
        if hh is None:
            hh = sha1(sha1(password.encode()))
        hval = sha1(pool[:20] + hh)
        self._send(CONNECT, CLEAR_P2, [hval], enc_override=ENC_NONE)
        h, p = self._recv_raw()
        if h['err'] not in (0,):
            raise CubeErr(h['err'], p.decode('utf-8', 'replace') or 'clear auth failed')
        return True

    def connect_aes(self, user, password):
        # PHASE 1
        X = os.urandom(20)
        hX = sha1(X)
        hhP = sha1(sha1(password.encode()))               # H(H(P))
        ctx1 = Ctx(hhP[:16], True)
        rand2 = bytearray(os.urandom(16))
        buf1 = bytearray(X + hX)                            # 40 bytes
        iv1 = bytes(rand2)
        _, ct1 = encrypt_buffer(buf1, 40, bytearray(rand2), ctx1)
        randhex = iv1.hex().encode()                        # hex of 16-byte rand2
        uhash = hashlib.sha1(user.encode() + randhex).hexdigest().encode() + b'\x00'
        # fields: [uhash] + wire(rand2(16)+ct1(40)) as second field of size 56
        field2 = iv1 + ct1                                  # 16 + 40 = 56
        data = uhash + field2
        sizearr = struct.pack('>i', len(uhash)) + struct.pack('>i', len(field2))
        packetsize = len(data) + len(sizearr)
        self._sendn(self._hdr(packetsize, 2, CONNECT, ENC_P1, ENC_AES128))
        self._sendn(sizearr)
        self._sendn(data)
        # PHASE 1.5 reply: AESCBC(Y;H(Y)) under H(H(P)); server sends enc=NONE, decrypt manually
        h, pl = self._recv_raw()
        if h['err'] not in (0,):
            raise CubeErr(h['err'], pl.decode('utf-8', 'replace') or 'aes phase1 failed')
        ctxd = Ctx(hhP[:16], False)
        buf = bytearray(pl)
        plen = decrypt_buffer(buf, len(pl), ctxd)
        Y = bytes(buf[:20])
        if sha1(Y) != bytes(buf[20:40]):
            raise CubeErr(-1, "server H(Y) mismatch (wrong password?)")
        # session key = SHA1(H(H(P)) ++ X ++ Y)[:16]
        s1 = sha1(hhP + X + Y)
        skey = s1[:16]
        self.enc_ctx = Ctx(skey, True)
        self.dec_ctx = Ctx(skey, False)
        # PHASE 2: send AESCBC(H(P)) under session key
        hP = sha1(password.encode())
        rand3 = bytearray(os.urandom(16))
        iv3 = bytes(rand3)
        bufp = bytearray(hP)
        _, ctp = encrypt_buffer(bufp, 20, bytearray(rand3), self.enc_ctx)
        field = iv3 + ctp                                   # 36
        sizearr = struct.pack('>i', len(field))
        self._sendn(self._hdr(len(field) + len(sizearr), 1, CONNECT, ENC_P2, ENC_NONE))
        self._sendn(sizearr)
        self._sendn(field)
        h, pl = self._recv_raw()
        if h['err'] not in (0,):
            # error string may be encrypted under session key
            if h['enc'] != ENC_NONE and pl:
                b = bytearray(pl); n = decrypt_buffer(b, len(pl), self.dec_ctx); pl = bytes(b[:n])
            raise CubeErr(h['err'], pl.decode('utf-8', 'replace') or 'aes auth failed')
        self.encryption = ENC_AES128
        return True

    def connect(self, user, password, mode='auto'):
        if mode in ('auto', 'clear'):
            try:
                return self.connect_clear(user, password)
            except CubeErr:
                if mode == 'clear':
                    raise
                # reconnect fresh for aes
                raise
        return self.connect_aes(user, password)

    # ---- queries ----
    def execute(self, sql):
        self._send(EXECUTE, 0, [sql.encode('utf-8') + b'\x00'])
        self._recv_reply()

    def _ack_chunk(self):
        self._sendn(self._hdr(0, 0, CHUNK, CHUNK_OK, ENC_NONE))

    def select(self, sql, raw=False):
        self._send(SELECT, 0, [sql.encode('utf-8') + b'\x00'])
        colnames = None
        coltypes = None
        allrows = []
        index = 0
        has_rowid = False
        while True:
            h, buf = self._recv_reply()
            if h['err'] == END_CHUNK:
                break
            rows, colcount = h['rows'], h['cols']
            has_rowid = bool(h['flag1'] & S_HAS_ROWID)
            has_tables = bool(h['flag1'] & S_HAS_TABLE)
            off = 0
            if index == 0:
                coltypes = list(struct.unpack('>%di' % colcount, buf[off:off + 4 * colcount]))
                off += 4 * colcount
            sizes = list(struct.unpack('>%di' % (rows * colcount),
                                       buf[off:off + 4 * rows * colcount]))
            off += 4 * rows * colcount
            if index == 0:
                names = []
                for _ in range(colcount):
                    e = buf.index(b'\x00', off)
                    names.append(buf[off:e].decode('utf-8', 'replace'))
                    off = e + 1
                if has_tables:
                    for _ in range(colcount):
                        off = buf.index(b'\x00', off) + 1
                colnames = names
            data = buf[off:]
            pos = 0
            flat = []
            for sz in sizes:
                if sz == -1:
                    flat.append(None)
                else:
                    flat.append(data[pos:pos + sz]); pos += sz
            for r in range(rows):
                row = flat[r * colcount:(r + 1) * colcount]
                if has_rowid:
                    row = row[1:]
                if raw:
                    allrows.append(row)  # list of bytes|None
                else:
                    allrows.append([None if v is None else v.decode('utf-8', 'replace') for v in row])
            index += 1
            if h['flag1'] & S_PARTIAL:
                self._ack_chunk()
            else:
                break
        if has_rowid:
            if colnames:
                colnames = colnames[1:]
            if coltypes:
                coltypes = coltypes[1:]
        self.last_coltypes = coltypes
        return colnames, allrows

    def close(self):
        try:
            self._sendn(self._hdr(0, 0, CLOSE, 0, self.encryption))
        except Exception:
            pass
        self.s.close()


import base64
def login(host=None, port=None):
    # Host/port from env so the same scripts work from the Linux host (via the
    # NAT+portproxy relay, default 127.0.0.1:14423) and natively on Windows
    # (direct to the server's IPv6 loopback, CUBE_HOST=::1 CUBE_PORT=4422).
    host = host or os.environ.get('CUBE_HOST', '127.0.0.1')
    port = int(port or os.environ.get('CUBE_PORT', '14423'))
    # hv_admin with its stored hash SHA1(SHA1(pw)) recovered from the server's
    # bootstrap SQL (no plaintext needed for the clear-in-TLS handshake).
    u = os.environ.get('CUBE_USER', 'hv_admin')
    # CUBE_HH = base64(SHA1(SHA1(pw))), aus hserver365.dll ausgelesen (siehe README
    # Abschnitt 3). Kein Default: muss vom Nutzer gesetzt werden.
    hh_b64 = os.environ.get('CUBE_HH')
    if not hh_b64:
        sys.exit("Fehler: Umgebungsvariable CUBE_HH ist nicht gesetzt.\n"
                 "Den Anmelde-Hash aus hserver365.dll auslesen (siehe README Abschnitt 3)\n"
                 "und setzen, z. B.:  set CUBE_HH=<der gefundene Hash>")
    try:
        hh = base64.b64decode(hh_b64, validate=True)
    except Exception:
        sys.exit(f"Fehler: CUBE_HH ist kein gültiger Base64-Wert: {hh_b64!r}")
    if len(hh) != 20:
        sys.exit(f"Fehler: CUBE_HH ergibt {len(hh)} statt 20 Byte (erwartet SHA-1-Hash).")
    c = Cube(host, port, tls=True)
    c.connect_clear(u, None, hh=hh)
    print(f"# connected as {u!r} @ {host}:{port} (tls-clear, stored-hash)", file=sys.stderr)
    return c


def use_hv(c):
    for stmt in ("USE DATABASE hv.db;", "USE DATABASE 'hv.db';", "SET DATABASE TO 'hv.db';"):
        try:
            c.execute(stmt); return
        except CubeErr:
            continue


def main():
    cmd = sys.argv[1] if len(sys.argv) > 1 else 'probe'
    c = login()
    if cmd == 'probe':
        for q in ("SHOW DATABASES;", "SHOW DATABASE LIST;"):
            try:
                _, rows = c.select(q); print(q, "->", rows)
            except CubeErr as e:
                print(q, "ERR", e)
    elif cmd == 'schema':
        use_hv(c)
        _, rows = c.select("SELECT type,name,sql FROM sqlite_master WHERE type IN ('table','view') ORDER BY name;")
        for t, name, sqltext in rows:
            print(f"\n----- {t} {name} -----\n{sqltext}")
    elif cmd == 'sql':
        use_hv(c)
        n, rows = c.select(sys.argv[2])
        w = csv.writer(sys.stdout)
        if n:
            w.writerow(n)
        w.writerows(rows)
    elif cmd == 'dump':
        outdir = sys.argv[2]
        os.makedirs(outdir, exist_ok=True)
        use_hv(c)
        _, tbls = c.select("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name;")
        for (name,) in tbls:
            try:
                cols, rows = c.select(f'SELECT * FROM "{name}";')
            except CubeErr as e:
                print(f"# skip {name}: {e}", file=sys.stderr); continue
            with open(os.path.join(outdir, name + '.csv'), 'w', newline='') as f:
                w = csv.writer(f)
                if cols:
                    w.writerow(cols)
                w.writerows(rows)
            print(f"{name}: {len(rows)} rows", file=sys.stderr)
    c.close()


if __name__ == '__main__':
    main()
