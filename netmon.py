#!/usr/bin/env python3
"""netmon - an iptraf-ng style network traffic monitor for macOS.

Stdlib only, no root needed. Data comes from `netstat -ibn` (interfaces) and
`nettop` (per-process / per-connection byte counters).

Keys: 1-4 views | up/down scroll | s sort | r reverse DNS | p pause | q quit
"""
import atexit
import curses
import os
import platform
import re
import socket
import subprocess
import sys
import shutil
import signal
import threading
import time
import unicodedata
from collections import defaultdict, deque
from concurrent.futures import ThreadPoolExecutor

HIST = 120
SMOOTH = 3                        # samples in the rate moving average
INTERVALS = [0.5, 1, 2, 5, 10]    # selectable refresh intervals (s)
SPARK = " ▁▂▃▄▅▆▇█"


def run(cmd, timeout=8):
    try:
        return subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True,
                              stdin=subprocess.DEVNULL, timeout=timeout).stdout
    except subprocess.TimeoutExpired:
        return ""  # transient hang; next tick retries
    except FileNotFoundError:
        return ""  # tool not installed (reported by preflight / --selftest)


# ---------------------------------------------------------------- collectors
def parse_netstat(text):
    """-> {iface: dict(ip, ipkts, ierrs, ibytes, opkts, oerrs, obytes)}"""
    ifs = {}
    for line in text.splitlines()[1:]:
        t = line.split()
        if len(t) < 10:
            continue
        name = t[0].rstrip("*")
        if "<Link#" in t[2]:
            try:
                ip, ie, ib, op, oe, ob = (int(x) for x in (t[-7], t[-6], t[-5], t[-4], t[-3], t[-2]))
            except ValueError:
                continue
            ifs.setdefault(name, {})
            ifs[name].update(ipkts=ip, ierrs=ie, ibytes=ib, opkts=op, oerrs=oe, obytes=ob)
        elif len(t) >= 11 and t[3].count(".") == 3:
            ifs.setdefault(name, {}).setdefault("ip", t[3])
    return {k: v for k, v in ifs.items() if "ibytes" in v}


def parse_nettop(text):
    """-> list of dict(proc, proto, conn, state, bin, bout); header-driven."""
    lines = text.splitlines()
    if not lines:
        return []
    cols = lines[0].split(",")[1:]
    rows, proc, pname, ppid = [], "?", "?", ""
    for line in lines[1:]:
        f = line.split(",")
        if len(f) < 2 or not f[0]:
            continue
        d = dict(zip(cols, f[1:]))
        head = f[0]
        if head[:3] in ("tcp", "udp") and "<->" in head:
            if not d.get("bytes_in"):
                continue  # listening / unconnected socket, no counters
            proto, conn = head.split(" ", 1)
            try:
                rows.append(dict(proc=proc, pname=pname, pid=ppid, proto=proto, conn=conn, state=d.get("state") or "-",
                                 bin=int(d["bytes_in"]), bout=int(d.get("bytes_out") or 0)))
            except ValueError:
                pass
        else:
            name, _, pid = head.rpartition(".")
            ok = pid.isdigit() and name
            proc = f"{name}[{pid}]" if ok else head
            pname, ppid = (name, pid) if ok else (head, "")
    return rows


# ------------------------------------------------------- OS detection + backends
def parse_os_release(text):
    d = {}
    for line in text.splitlines():
        k, sep, v = line.partition("=")
        if sep:
            d[k.strip()] = v.strip().strip('"').strip("'")
    return d


def detect_os(system=None, os_release=None):
    """-> dict(family=macos|debian|rhel|linux-other|unsupported, name=human text).
    Debian-based: debian, ubuntu, mint, raspbian... (ID or ID_LIKE contains debian/ubuntu).
    RHEL-based: rhel, centos, rocky, almalinux, fedora, amzn... (ID or ID_LIKE contains rhel/fedora/centos)."""
    system = system or platform.system()
    if system == "Darwin":
        return dict(family="macos", name=f"macOS {platform.mac_ver()[0]}".strip())
    if system != "Linux":
        return dict(family="unsupported", name=system or "unknown")
    if os_release is None:
        os_release = ""
        for p in ("/etc/os-release", "/usr/lib/os-release"):
            try:
                with open(p) as f:
                    os_release = f.read()
                break
            except OSError:
                continue
    d = parse_os_release(os_release)
    ids = {d.get("ID", "").lower(), *d.get("ID_LIKE", "").lower().split()}
    name = d.get("PRETTY_NAME") or d.get("NAME") or "Linux"
    if ids & {"debian", "ubuntu"}:
        return dict(family="debian", name=name)
    if ids & {"rhel", "fedora", "centos", "rocky", "almalinux", "ol", "amzn"}:
        return dict(family="rhel", name=name)
    return dict(family="linux-other", name=name)


SS_STATES = {"ESTAB": "Established", "SYN-SENT": "SynSent", "SYN-RECV": "SynReceived", "FIN-WAIT-1": "FinWait1",
             "FIN-WAIT-2": "FinWait2", "TIME-WAIT": "TimeWait", "CLOSE-WAIT": "CloseWait", "LAST-ACK": "LastAck",
             "CLOSING": "Closing", "CLOSE": "Closed", "LISTEN": "Listen", "UNCONN": "-"}


def parse_proc_net_dev(text):
    """/proc/net/dev -> {iface: dict(ibytes, ipkts, ierrs, obytes, opkts, oerrs)}"""
    ifs = {}
    for line in text.splitlines():
        name, sep, rest = line.partition(":")
        f = rest.split()
        if not sep or len(f) < 16:
            continue
        try:
            ifs[name.strip()] = dict(ibytes=int(f[0]), ipkts=int(f[1]), ierrs=int(f[2]),
                                     obytes=int(f[8]), opkts=int(f[9]), oerrs=int(f[10]))
        except ValueError:
            pass
    return ifs


def parse_ip_addr(text):
    """`ip -o -4 addr show` -> {iface: first ipv4}"""
    out = {}
    for line in text.splitlines():
        t = line.split()
        if "inet" in t:
            name = t[1].rstrip(":")
            out.setdefault(name, t[t.index("inet") + 1].split("/")[0])
    return out


def _ss_ep(ep):
    """'192.168.1.5:22' / '[::1]:22' / '*:*' / '0.0.0.0:*' -> (display, is_wildcard_peer)"""
    host, _, port = ep.rpartition(":")
    host = host.strip("[]")
    if port == "*" or host in ("*", "0.0.0.0", "::") and port in ("*", "0"):
        return "*:*", True
    return f"{host}:{port}", False


def parse_ss(text):
    """`ss -tunapi` output -> (rows, counters_seen). Rows match parse_nettop's dict shape.
    Works with or without the header line (-H is not available on old iproute2)."""
    rows, seen = [], False
    cur = None
    for line in text.splitlines():
        if not line.strip():
            continue
        if line[0] in " \t":                      # TCP info line belonging to the previous socket
            if cur is not None:
                mi = re.search(r"\bbytes_received:(\d+)", line)
                mo = re.search(r"\bbytes_sent:(\d+)", line) or re.search(r"\bbytes_acked:(\d+)", line)
                if mi or mo:
                    seen = True
                    cur["bin"] = int(mi.group(1)) if mi else 0
                    cur["bout"] = int(mo.group(1)) if mo else 0
            continue
        t = line.split(None, 6)
        if len(t) < 6 or t[0] not in ("tcp", "udp"):
            cur = None
            continue
        proto, state, local, peer = t[0], t[1], t[4], t[5]
        if state == "LISTEN":
            cur = None
            continue
        lo, _ = _ss_ep(local)
        pe, wild = _ss_ep(peer)
        v6 = local.startswith("[") or local.count(":") > 1
        m = re.search(r'users:\(\("([^"]*)",pid=(\d+)', t[6]) if len(t) > 6 else None
        name, pid = (m.group(1), m.group(2)) if m else ("-", "")
        cur = dict(proc=f"{name}[{pid}]" if pid else "?", pname=name, pid=pid,
                   proto=proto + ("6" if v6 else "4"), conn=f"{lo}<->{pe}",
                   state=SS_STATES.get(state, state.title().replace("-", "")), bin=0, bout=0)
        rows.append(cur)
    return rows, seen


class Backend:
    """OS-specific data sources. Every backend returns the same shapes so views/filters never change."""
    family = "?"
    required = ()          # tools without which netmon can't run
    optional = ("tcpdump",)  # features degrade without these
    note = ""              # one-line caveat shown in the bottom bar (e.g. old ss without byte counters)

    def __init__(self, osinfo):
        self.os = osinfo

    def install_hint(self, missing):
        return ""

    def read_interfaces(self):
        raise NotImplementedError

    def read_connections(self):
        raise NotImplementedError

    def default_iface(self):
        return "en0"


class MacBackend(Backend):
    family = "macos"
    required = ("netstat", "nettop")
    optional = ("route", "tcpdump")

    def install_hint(self, missing):
        return "These ship with macOS; check PATH (nettop/netstat live in /usr/bin)."

    def read_interfaces(self):
        return parse_netstat(run(["netstat", "-ibn"]))

    def read_connections(self):
        return parse_nettop(run(["nettop", "-x", "-L", "1", "-s", "1", "-J", "state,bytes_in,bytes_out"], timeout=15))

    def default_iface(self):
        for l in run(["route", "-n", "get", "default"]).splitlines():
            if "interface:" in l:
                return l.split()[-1]
        return "en0"


class LinuxBackend(Backend):
    """Debian-based and RHEL-based: /proc/net/dev + iproute2 (`ss`, `ip`). tcpdump is optional."""
    required = ("ss",)
    optional = ("ip", "tcpdump")

    def __init__(self, osinfo):
        super().__init__(osinfo)
        self.family = osinfo["family"]

    def install_hint(self, missing):
        if self.family == "debian":
            return "sudo apt install " + " ".join(sorted({"iproute2" if m in ("ss", "ip") else m for m in missing}))
        if self.family == "rhel":
            return "sudo dnf install " + " ".join(sorted({"iproute" if m in ("ss", "ip") else m for m in missing})) + "   (yum on EL7)"
        return "install iproute2/iproute and tcpdump with your package manager"

    def read_interfaces(self):
        try:
            with open("/proc/net/dev") as f:
                ifs = parse_proc_net_dev(f.read())
        except OSError:
            ifs = {}
        for name, ip in parse_ip_addr(run(["ip", "-o", "-4", "addr", "show"])).items():
            if name in ifs:
                ifs[name]["ip"] = ip
        return ifs

    def read_connections(self):
        rows, seen = parse_ss(run(["ss", "-tunapi"], timeout=15))
        has_tcp = any(r["proto"].startswith("tcp") and r["state"] == "Established" for r in rows)
        # Old iproute2 (EL7) prints no bytes_* fields at all: say so instead of showing silent zeros.
        self.note = "ss: no byte counters (old iproute2)" if rows and has_tcp and not seen else ""
        return rows

    def default_iface(self):
        m = re.search(r"\bdev\s+(\S+)", run(["ip", "route", "show", "default"]))
        if m:
            return m.group(1)
        try:
            with open("/proc/net/dev") as f:
                names = [n for n in parse_proc_net_dev(f.read()) if n != "lo"]
            return names[0] if names else "eth0"
        except OSError:
            return "eth0"


def make_backend(osinfo=None):
    osinfo = osinfo or detect_os()
    if osinfo["family"] == "macos":
        return MacBackend(osinfo)
    if osinfo["family"] in ("debian", "rhel", "linux-other"):
        return LinuxBackend(osinfo)
    raise SystemExit(f"netmon supports macOS, Debian-based and RHEL-based Linux (detected: {osinfo['name']}).")


_BACKEND = None


def get_backend():
    global _BACKEND
    if _BACKEND is None:
        _BACKEND = make_backend()
    return _BACKEND


def preflight(be, fatal=True):
    """Check required/optional tools; returns list of missing optional tools. Exits if a required one is missing."""
    miss_req = [t for t in be.required if not shutil.which(t)]
    if miss_req and fatal:
        raise SystemExit(f"netmon on {be.os['name']}: missing required tool(s): {', '.join(miss_req)}\n  -> {be.install_hint(miss_req)}")
    return [t for t in be.optional if not shutil.which(t)]


class Collector(threading.Thread):
    def __init__(self, interval=1.0, backend=None):
        super().__init__(daemon=True)
        self.backend = backend or get_backend()
        self.lock = threading.Lock()
        self.interval = interval          # seconds between samples (changed live with +/-)
        self._rates = defaultdict(lambda: deque(maxlen=SMOOTH))   # key -> recent (in, out) rates
        self.paused = False
        self.error = ""
        self.ifaces = {}   # name -> dict with rates
        self.conns = {}    # key -> dict
        self.hist = defaultdict(lambda: deque(maxlen=HIST))  # iface -> (in, out)
        self._pi, self._pc, self._pt = {}, {}, None
        self._base = {}   # conn key -> (bytes_in, bytes_out) at first sighting of startup

    def _smooth(self, key, ri, ro):
        """Moving average over the last SMOOTH samples so rates stop jumping."""
        q = self._rates[key]
        q.append((ri, ro))
        return sum(x[0] for x in q) / len(q), sum(x[1] for x in q) / len(q)

    def sample(self):
        ifs = self.backend.read_interfaces()
        nt = self.backend.read_connections()
        now = time.time()      # counters were read just before this instant
        dt = now - self._pt if self._pt else None
        with self.lock:
            for n, v in ifs.items():
                p = self._pi.get(n)
                v["in_rate"] = v["out_rate"] = 0.0
                if p and dt:
                    v["in_rate"], v["out_rate"] = self._smooth(
                        ("if", n), max(0, v["ibytes"] - p["ibytes"]) / dt, max(0, v["obytes"] - p["obytes"]) / dt)
                    self.hist[n].append((v["in_rate"], v["out_rate"]))
            self.ifaces = ifs
            conns = {}
            first = self._pt is None
            for r in nt:
                k = (r["proc"], r["proto"], r["conn"])
                if k not in self._base:
                    # startup sightings are baselined (their history predates us);
                    # connections that appear later count from zero.
                    self._base[k] = (r["bin"], r["bout"]) if first else (0, 0)
                p = self._pc.get(k)
                ri = ro = 0.0
                if p and dt:
                    ri, ro = self._smooth(k, max(0, r["bin"] - p[0]) / dt, max(0, r["bout"] - p[1]) / dt)
                b = self._base[k]
                conns[k] = dict(r, rin=ri, rout=ro, rawin=r["bin"], rawout=r["bout"],
                                bin=max(0, r["bin"] - b[0]), bout=max(0, r["bout"] - b[1]),
                                wild=r["conn"].split("<->", 1)[1].startswith("*"))
            self.conns = conns
            self._pi = {n: dict(v) for n, v in ifs.items()}
            self._pc = {k: (v["rawin"], v["rawout"]) for k, v in conns.items()}
            self._pt = now
            # forget baselines of closed connections (stops unbounded growth and stale reuse)
            self._base = {k: v for k, v in self._base.items() if k in conns}
            for key in [k for k in self._rates if k not in conns and k[0] != "if"]:
                del self._rates[key]     # forget closed connections
            self.error = self.backend.note

    def run(self):
        while True:
            t0 = time.time()
            if not self.paused:
                try:
                    self.sample()
                except Exception as e:  # noqa: BLE001
                    self.error = f"collector: {e}"
            while time.time() - t0 < self.interval:    # re-checked often so +/- takes effect at once
                time.sleep(0.05)


# ------------------------------------------------------------ packet capture
SIZE_BUCKETS = [(64, "0-64"), (128, "65-128"), (256, "129-256"), (512, "257-512"),
                (1024, "513-1024"), (1514, "1025-1514"), (10**9, ">1514")]
_ENDPOINT = re.compile(r"^(\S+) > (\S+):\s*(.*)$")


def _split_ep(ep):
    """'10.0.0.1.443' -> ('10.0.0.1','443'); '::1.80' -> ('::1','80'); '10.0.0.1' -> ('10.0.0.1','')"""
    host, dot, port = ep.rpartition(".")
    if dot and port.isdigit() and (":" in host or host.count(".") == 3):
        return host, port
    return ep, ""


def parse_packet(line):
    """Parse one `tcpdump -nn -tt -e` line -> dict or None.
    Example: '1731412931.201234 aa:.. > bb:.., ethertype IPv4 (0x0800), length 78: 10.0.0.1.56601 > 1.2.3.4.443: Flags [S], seq 1, ..., length 0'
    """
    m = re.match(r"^(\d+\.\d+)\s.*?\blength (\d+): (.*)$", line)
    if not m:
        return None
    ts, flen, rest = float(m.group(1)), int(m.group(2)), m.group(3)
    rest = re.sub(r"^(IP6?|ARP)\s+", "", rest) if not rest.startswith("ARP,") else rest
    if rest.startswith("ARP,"):
        return dict(ts=ts, proto="ARP", src="-", sport="", dst="-", dport="", flags="-", len=flen)
    e = _ENDPOINT.match(rest)
    if not e:
        return dict(ts=ts, proto="Other", src="?", sport="", dst="?", dport="", flags="-", len=flen)
    (src, sp), (dst, dp) = _split_ep(e.group(1)), _split_ep(e.group(2))
    body = e.group(3)
    flags = "-"
    if body.startswith("Flags ["):
        proto = "TCP"
        raw = body[7:body.index("]")]
        flags = "-" if raw == "none" else raw.replace(".", "A")
    elif body.startswith("ICMP6") or body.startswith("ICMP"):
        proto, flags = ("ICMP6" if body.startswith("ICMP6") else "ICMP"), (body.split(",")[0].split(" ", 1)[-1][:11])
    elif sp or dp:
        proto = "UDP"
    else:
        proto = "Other"
    return dict(ts=ts, proto=proto, src=src, sport=sp, dst=dst, dport=dp, flags=flags, len=flen)


CAPTURES = []


def arg_value(flag):
    """Value following `flag` in sys.argv, or None."""
    a = sys.argv
    return a[a.index(flag) + 1] if flag in a and a.index(flag) + 1 < len(a) else None


class Capture:
    """Runtime-toggleable packet capture built on the system tcpdump (root needed; uses `sudo -n` otherwise)."""

    def __init__(self):
        self.lock = threading.Lock()
        self.proc = None
        self.iface = arg_value("-i") or default_iface()
        self.detail = ""
        self.status = "off"          # off | starting | ON | needs root | error
        self.clear()
        atexit.register(self.stop)
        CAPTURES.append(self)

    def clear(self):
        with self.lock:
            self.log = deque(maxlen=2000)
            self.protos = defaultdict(lambda: [0, 0])      # proto -> [packets, bytes]
            self.hist = [0] * len(SIZE_BUCKETS)
            self.flags = defaultdict(int)
            self.total = 0

    @property
    def on(self):
        return self.proc is not None

    def start(self, iface=None):
        self.stop()
        self.iface = iface or self.iface
        if not shutil.which("tcpdump"):
            self.proc, self.status = None, "tool missing"
            self.detail = "tcpdump not installed: " + get_backend().install_hint(["tcpdump"])
            return
        cmd = ["tcpdump", "-i", self.iface, "-l", "-nn", "-tt", "-e", "-s", "128"]
        if os.geteuid() != 0:
            cmd = ["sudo", "-n"] + cmd
        try:
            self.proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.DEVNULL,
                                         universal_newlines=True, bufsize=1, start_new_session=True)
        except OSError as e:
            self.proc, self.status = None, f"error: {e}"
            return
        self.status = "starting"
        threading.Thread(target=self._read, args=(self.proc,), daemon=True).start()

    def stop(self):
        p, self.proc = self.proc, None
        if p and p.poll() is None:
            try:
                os.killpg(p.pid, signal.SIGTERM)
            except (ProcessLookupError, PermissionError):
                try:
                    p.terminate()
                except Exception:  # noqa: BLE001
                    pass
            try:
                p.wait(timeout=2)
            except Exception:  # noqa: BLE001
                pass
        if self.status in ("ON", "starting"):
            self.status = "off"

    def _read(self, p):
        for line in p.stdout:
            pk = parse_packet(line)
            if not pk:
                continue
            if self.status == "starting":
                self.status = "ON"
            with self.lock:
                self.log.append(pk)
                self.total += 1
                st = self.protos[pk["proto"]]
                st[0] += 1
                st[1] += pk["len"]
                for i, (lim, _) in enumerate(SIZE_BUCKETS):
                    if pk["len"] <= lim:
                        self.hist[i] += 1
                        break
                if pk["proto"] == "TCP":
                    for ch in set(pk["flags"]):
                        self.flags[ch] += 1
        err = p.stderr.read() if p.stderr else ""
        if p is self.proc:           # ended by itself, not via stop()
            self.proc = None
            low = err.lower()
            if "password" in low or "permission" in low or "not permitted" in low or "sudo" in low:
                self.status = "needs root"
            else:
                self.status = "error"
            self.detail = err.strip().splitlines()[-1] if err.strip() else ""


def default_iface():
    try:
        return get_backend().default_iface()
    except Exception:  # noqa: BLE001
        return "en0"


# ------------------------------------------------------------------ helpers
def hb(n):
    n = float(n)
    for u in ("B", "K", "M", "G", "T"):
        if n < 1024 or u == "T":
            return f"{n:.0f}{u}" if u == "B" else f"{n:.1f}{u}"
        n /= 1024


def hr(n):
    return hb(n) + "/s"


def cw(ch):
    if unicodedata.combining(ch) or unicodedata.category(ch) in ("Mn", "Me", "Cf"):
        return 0
    return 2 if unicodedata.east_asian_width(ch) in ("W", "F") else 1


def swidth(s):
    return sum(cw(c) for c in s)


def fit(s, n, right=False):
    """Truncate/pad s to exactly n terminal cells (wide chars count 2)."""
    s = str(s)
    if swidth(s) > n:
        out, w = "", 0
        for c in s:
            if w + cw(c) > n - 1:
                break
            out, w = out + c, w + cw(c)
        s = out + "…"
    pad = " " * max(0, n - swidth(s))
    return pad + s if right else s + pad


def spread_pos(widths, width):
    """x-start of each fixed-width segment, spread over `width`: first flush left, last flush right."""
    n, total = len(widths), sum(widths)
    gaps = n - 1
    margin = 1 if total + gaps + 2 <= width else 0
    free = width - total - 2 * margin
    if n < 2 or free < gaps:
        pos, x = [], margin
        for wd in widths:
            pos.append(x)
            x += wd + 1
        return pos
    pos, acc = [], 0
    for k, wd in enumerate(widths):
        pos.append(margin + acc + (free * k) // gaps)
        acc += wd
    return pos


def draw_segs(scr, y, w, segs, attr):
    """segs: (label, value) pairs; label drawn bold, value normal, at spread positions."""
    scr_w = w - 1
    widths = [swidth(a) + swidth(b) for a, b in segs]
    for x, (a, b) in zip(spread_pos(widths, scr_w), segs):
        addstr(scr, y, x, a, attr | curses.A_BOLD)
        addstr(scr, y, x + swidth(a), b, attr)


def spark(vals, width):
    vals = list(vals)[-width:]
    if not vals:
        return ""
    m = max(vals) or 1
    return "".join(SPARK[min(8, int(v / m * 8))] for v in vals)


class DNS:
    MAX_CACHE = 5000

    def __init__(self):
        self.cache, self.on = {}, False
        self.pool = ThreadPoolExecutor(max_workers=4, thread_name_prefix="dns")

    def name(self, addr):
        if addr in self.cache:
            return self.cache[addr]
        if len(self.cache) >= self.MAX_CACHE:
            return addr
        self.cache[addr] = addr
        self.pool.submit(self._look, addr)
        return addr

    def _look(self, addr):
        try:
            self.cache[addr] = socket.gethostbyaddr(addr)[0]
        except Exception:  # noqa: BLE001
            pass

    def fmt(self, ep):
        if not self.on:
            return ep
        for sep in (":", "."):
            if ep.count(sep) >= 1 and ep.rsplit(sep, 1)[-1].isdigit() and (sep == ":" and ep.count(":") == 1 or sep == "." and ":" in ep):
                host, port = ep.rsplit(sep, 1)
                if host not in ("*", ""):
                    return f"{self.name(host)}:{port}"
        return ep


# ---------------------------------------------------------------------- UI
VIEWS = ["Interfaces", "Connections", "Processes", "Statistics", "Packets", "Protocols"]
SORTS = {1: ["rate", "total", "proc"], 2: ["rate", "total", "proc"]}


def _port(ep):
    m = re.search(r"[.:](\d+|\*)$", ep)
    return m.group(1) if m else ""


def parse_filter(text):
    terms = []
    for t in text.split():
        key, sep, val = t.partition(":")
        if sep and key in ("proto", "port", "state", "proc", "host") and val:
            terms.append((key, val.lower()))
        else:
            terms.append(("text", t.lower()))
    return terms


def match(c, terms):
    loc, rem = c["conn"].split("<->", 1)
    for key, v in terms:
        if key == "proto" and not c["proto"].startswith(v):
            return False
        if key == "port" and v not in (_port(loc), _port(rem)):
            return False
        if key == "state" and v not in c["state"].lower():
            return False
        if key == "proc" and v not in c["proc"].lower():
            return False
        if key == "host" and v not in rem.lower():
            return False
        if key == "text" and v not in f"{c['proc']} {c['proto']} {c['conn']} {c['state']}".lower():
            return False
    return True


def apply_filter(conns, st):
    terms = parse_filter(st.get("filter", ""))
    if st.get("proto"):
        terms.append(("proto", st["proto"]))
    return [c for c in conns if (st.get("wild") or not c["wild"]) and match(c, terms)]


def agg_procs(conns):
    d = defaultdict(lambda: dict(proc="", pname="", pid="", n=0, rin=0.0, rout=0.0, bin=0, bout=0))
    for c in conns:
        a = d[c["proc"]]
        a["proc"] = c["proc"]
        a["pname"], a["pid"] = c.get("pname", c["proc"]), c.get("pid", "")
        a["n"] += 1
        for k in ("rin", "rout", "bin", "bout"):
            a[k] += c[k]
    return list(d.values())


def sort_rows(rows, mode):
    if mode == "total":
        return sorted(rows, key=lambda r: r["bin"] + r["bout"], reverse=True)
    if mode == "proc":
        return sorted(rows, key=lambda r: r["proc"])
    return sorted(rows, key=lambda r: r["rin"] + r["rout"], reverse=True)


def addstr(win, y, x, s, attr=0):
    h, w = win.getmaxyx()
    if 0 <= y < h and x < w:
        avail = w - x - (1 if y == h - 1 else 0)
        out, n = "", 0
        for c in s:
            if n + cw(c) > avail:
                break
            out, n = out + c, n + cw(c)
        try:
            win.addstr(y, x, out, attr)
        except curses.error:
            pass


def view_interfaces(ctx):
    hdr = f"{'IFACE':<10}{'IP':<17}{'IN RATE':>11}{'OUT RATE':>11}{'IN TOTAL':>10}{'OUT TOTAL':>10}{'IPKTS':>11}{'OPKTS':>11}{'ERR':>6}"
    rows = [f"{fit(n,10)}{fit(v.get('ip', '-'),17)}{hr(v['in_rate']):>11}{hr(v['out_rate']):>11}"
            f"{hb(v['ibytes']):>10}{hb(v['obytes']):>10}{v['ipkts']:>11}{v['opkts']:>11}{v['ierrs']+v['oerrs']:>6}"
            for n, v in sorted(ctx["ifs"].items())]
    return hdr, rows


def view_connections(ctx):
    hdr = f"{'PROTO':<6}{'STATE':<13}{'PID':>7}  {'PROCESS':<20}{'LOCAL':<30}{'REMOTE':<36}{'IN/s':>10}{'OUT/s':>10}{'IN':>9}{'OUT':>9}"
    rows = []
    for c in sort_rows(ctx["conns"], SORTS[1][ctx["st"]["sort"] % 3]):
        loc, rem = c["conn"].split("<->", 1)
        rows.append(f"{fit(c['proto'],6)}{fit(c['state'],13)}{fit(c['pid'] or '-',7,right=True)}  {fit(c['pname'],20)}{fit(loc,30)}{fit(ctx['dns'].fmt(rem),36)}"
                    f"{hr(c['rin']):>10}{hr(c['rout']):>10}{hb(c['bin']):>9}{hb(c['bout']):>9}")
    return hdr, rows


def view_processes(ctx):
    hdr = f"{'PID':>7}  {'PROCESS':<30}{'CONNS':>6}{'IN/s':>12}{'OUT/s':>12}{'IN TOTAL':>12}{'OUT TOTAL':>12}"
    rows = [f"{fit(a['pid'] or '-',7,right=True)}  {fit(a['pname'],30)}{a['n']:>6}{hr(a['rin']):>12}{hr(a['rout']):>12}{hb(a['bin']):>12}{hb(a['bout']):>12}"
            for a in sort_rows(agg_procs(ctx["conns"]), SORTS[2][ctx["st"]["sort"] % 3])]
    return hdr, rows


def view_statistics(ctx):
    hdr = "Per-interface throughput history (newest right); scaled to each line's own max"
    sw = max(10, ctx["w"] - 30)
    rows = []
    for n in sorted(ctx["ifs"]):
        hh = ctx["hist"].get(n, [])
        rows.append(f"{fit(n,8)}IN  {spark([x[0] for x in hh], sw)}  {hr(ctx['ifs'][n]['in_rate'])}")
        rows.append(f"{'':<8}OUT {spark([x[1] for x in hh], sw)}  {hr(ctx['ifs'][n]['out_rate'])}")
    return hdr, rows


def view_packets(ctx):
    cap, st = ctx["cap"], ctx["st"]
    hdr = f"{'TIME':<13}{'PROTO':<7}{'FLAGS':<12}{'SOURCE':<26}{'DESTINATION':<26}{'LEN':>6}"
    rows = []
    if not cap.on:
        rows = [f"Packet capture is {cap.status}. Press [c] to enable ({cap.iface})."]
        if cap.detail:
            rows.append(cap.detail)
        if cap.status == "needs root":
            rows.append("Run `sudo -v` in another terminal (then press c), or start netmon with sudo.")
    with cap.lock:
        pkts = list(cap.log)
    terms = parse_filter(st.get("filter", ""))
    if st.get("proto"):
        terms.append(("proto", st["proto"]))
    for pk in pkts:
        c = dict(proc="", proto=pk["proto"].lower(), state=pk["flags"], conn=f"{pk['src']}:{pk['sport']}<->{pk['dst']}:{pk['dport']}")
        if not match(c, terms):
            continue
        src = pk["src"] + (":" + pk["sport"] if pk["sport"] else "")
        dst = pk["dst"] + (":" + pk["dport"] if pk["dport"] else "")
        rows.append(f"{time.strftime('%H:%M:%S', time.localtime(pk['ts']))}.{int(pk['ts'] % 1 * 1000):03d} "
                    f"{fit(pk['proto'],7)}{fit(pk['flags'],12)}{fit(src,26)}{fit(dst,26)}{pk['len']:>6}")
    return hdr, rows


def view_protocols(ctx):
    cap = ctx["cap"]
    hdr = f"{'PROTO':<8}{'PKTS':>10}{'BYTES':>10}{'SHARE':>8}     {'SIZE':<11}{'PKTS':>8}"
    rows = []
    if not cap.on:
        rows.append(f"Packet capture is {cap.status}. Press [c] to enable ({cap.iface}).")
    with cap.lock:
        pr = {k: list(v) for k, v in cap.protos.items()}
        hs, fl, total = list(cap.hist), dict(cap.flags), cap.total
    pl = sorted(pr.items(), key=lambda kv: -kv[1][0])
    mx = max(hs) or 1
    for i in range(max(len(pl), len(SIZE_BUCKETS))):
        left = " " * 36
        if i < len(pl):
            k, (np_, nb) = pl[i]
            share = f"{100 * np_ / total:.0f}%" if total else "-"
            left = f"{fit(k,8)}{np_:>10,}{hb(nb):>10}{share:>8}     "
        right = ""
        if i < len(SIZE_BUCKETS):
            right = f"{fit(SIZE_BUCKETS[i][1],11)}{hs[i]:>8,}  " + "█" * int(20 * hs[i] / mx)
        rows.append(left + right)
    names = dict(S="SYN", F="FIN", R="RST", P="PSH", A="ACK", U="URG")
    rows += ["", "TCP flags: " + "  ".join(f"{names.get(k, k)} {v:,}" for k, v in sorted(fl.items(), key=lambda kv: -kv[1]))]
    return hdr, rows


VIEW_BUILDERS = [view_interfaces, view_connections, view_processes, view_statistics, view_packets, view_protocols]


VIRTUAL_IFACES = ("lo", "utun", "bridge", "awdl", "llw", "gif", "stf", "ap", "anpi",
                  "docker", "veth", "br-", "virbr", "tun", "tap")   # avoid double counting tunnels/bridges


def draw_topbar(scr, ctx):
    w, bar = ctx["w"], curses.A_REVERSE
    real = [v for n, v in ctx["ifs"].items()
            if not n.startswith(VIRTUAL_IFACES) and not v.get("ip", "").startswith("127.")]
    tot_i = sum(v["in_rate"] for v in real)
    tot_o = sum(v["out_rate"] for v in real)
    if w >= 135:
        tabs = " ".join(f"[{i+1}]{n}" for i, n in enumerate(VIEWS))
        traffic = f"▼ IN {fit(hr(tot_i), 10, right=True)}   ▲ OUT {fit(hr(tot_o), 10, right=True)} "
    else:   # narrow: short tab names + compact traffic so they don't collide
        tabs = " ".join(f"[{i+1}]{n}" for i, n in enumerate(("Intf", "Conn", "Proc", "Stats", "Pkts", "Prot")))
        traffic = f"▼{fit(hr(tot_i), 9, right=True)} ▲{fit(hr(tot_o), 9, right=True)} "
    addstr(scr, 0, 0, fit(" netmon  " + tabs, w), bar)
    addstr(scr, 0, max(0, w - swidth(traffic) - 1), traffic, bar | curses.A_BOLD)


def draw_body(scr, ctx, hdr, rows):
    h, w, st = ctx["h"], ctx["w"], ctx["st"]
    addstr(scr, 2, 0, fit(hdr, w), curses.A_BOLD | curses.A_UNDERLINE)
    body = h - 5
    if st["view"] == 4 and ctx["cap"].on:   # live log: follow newest; Up scrolls back (negative offset)
        off = max(0, min(-st["scroll"], max(0, len(rows) - body)))
        st["scroll"] = -off
        top = max(0, len(rows) - body - off)
    else:
        st["scroll"] = max(0, min(st["scroll"], max(0, len(rows) - body)))
        top = st["scroll"]
    for i, r in enumerate(rows[top: top + body]):
        addstr(scr, 3 + i, 0, r)


def bar_columns(ctx, nrows):
    """Bottom-bar columns: (current value, key, function, flexible?). Value is the upper line."""
    col, st, dns, cap, view = ctx["col"], ctx["st"], ctx["dns"], ctx["cap"], ctx["st"]["view"]
    sortlbl = "-"
    if view in SORTS:
        sortlbl = {"rate": "rate", "total": "total", "proc": "name"}[SORTS[view][st["sort"] % 3]]
    return [
        (col.error or st.get("filter", "") or "-", "/", "Filter", True),
        (st.get("proto") or "all", "t", "Proto", False),
        ("shown" if st.get("wild") else "hidden", "w", "Wildcards", False),
        (sortlbl, "s", "Sort", False),
        ("on" if dns.on else "off", "r", "DNS", False),
        ("PAUSED" if col.paused else "running", "p", "Pause", False),
        (f"{col.interval:g}s", "+/-", "Refresh", False),
        (f"ON {cap.iface}" if cap.on and cap.status == "ON" else ("..." if cap.on else cap.status[:10]), "c", "Capture", False),
        (VIEWS[view], "1-6", "Views", False),
        (f"{nrows} rows", "q", "Quit", False),
    ], sortlbl


BAR_MINW = [0, 3, 6, 5, 3, 7, 4, 10, max(len(x) for x in VIEWS), 9]   # widest value each column can show


def draw_bottombar(scr, ctx, nrows):
    h, w, bar = ctx["h"], ctx["w"], curses.A_REVERSE
    cols, sortlbl = bar_columns(ctx, nrows)

    def build(br):
        out = []
        for val, key, fn, flex in cols:
            k = f"[{key}]" if br else key
            name = fn if br or fn != "Wildcards" else "Wild"
            out.append((val, k, name, swidth(k) + 1 + swidth(name), flex))
        return out

    def widths(cs, fmax=30):
        base = [max(bw, swidth(v), m) for (v, k, fn, bw, fl), m in zip(cs, BAR_MINW)]
        spare = (w - 1) - 2 - sum(b for b, c in zip(base, cs) if not c[4]) - (len(cs) - 1)
        return [min(fmax, max(spare, c[3])) if c[4] else b for b, c in zip(base, cs)]

    cs = build(True)
    if widths(cs)[0] < 12:
        cs = build(False)
    wd = widths(cs)
    xs = spread_pos(wd, w - 1)
    if h >= 8:
        addstr(scr, h - 2, 0, " " * w, bar)
        addstr(scr, h - 1, 0, " " * w, bar)
        for x, cwid, (val, k, fn, bw, flex) in zip(xs, wd, cs):
            addstr(scr, h - 2, x, fit(val, cwid), bar | curses.A_BOLD)
            addstr(scr, h - 1, x, k, bar | curses.A_BOLD)
            addstr(scr, h - 1, x + swidth(k), " " + fn, bar)
    else:
        flt = ctx["col"].error or ctx["st"].get("filter", "") or "-"
        addstr(scr, h - 1, 0, fit(f" {nrows} rows | sort:{sortlbl} | filter:{flt}", w - 1), bar)


def draw(scr, col, st, dns, cap):
    scr.erase()
    h, w = scr.getmaxyx()
    with col.lock:
        ifs = dict(col.ifaces)
        conns = apply_filter(list(col.conns.values()), st)
        hist = {k: list(v) for k, v in col.hist.items()}
    ctx = dict(h=h, w=w, st=st, col=col, dns=dns, cap=cap, ifs=ifs, conns=conns, hist=hist)
    hdr, rows = VIEW_BUILDERS[st["view"]](ctx)
    draw_topbar(scr, ctx)
    draw_body(scr, ctx, hdr, rows)
    draw_bottombar(scr, ctx, len(rows))
    scr.refresh()


def interval_arg():
    a = sys.argv
    try:
        v = float(a[a.index("--interval") + 1]) if "--interval" in a else 1.0
    except (ValueError, IndexError):
        v = 1.0
    return max(0.2, v)


def ui(scr):
    curses.curs_set(0)
    scr.timeout(250)
    col, dns, cap = Collector(interval_arg()), DNS(), Capture()
    if "--capture" in sys.argv:
        cap.start()
    col.start()
    st = dict(view=0, sort=0, scroll=0, filter="", proto="", wild=False)
    while True:
        draw(scr, col, st, dns, cap)
        k = scr.getch()
        if k in (ord("q"), 27):
            return
        elif ord("1") <= k <= ord("6"):
            st.update(view=k - ord("1"), scroll=0, sort=0)
        elif k in (ord("+"), ord("="), ord("-"), ord("_")):
            near = min(range(len(INTERVALS)), key=lambda i: abs(INTERVALS[i] - col.interval))
            step = 1 if k in (ord("+"), ord("=")) else -1      # + = refresh more often
            col.interval = INTERVALS[max(0, min(len(INTERVALS) - 1, near - step))]
        elif k == ord("c"):
            cap.stop() if cap.on else cap.start()
        elif k == ord("C"):
            cap.clear()
        elif k == ord("i"):
            names = sorted(col.ifaces) or [cap.iface]
            cap.iface = names[(names.index(cap.iface) + 1) % len(names)] if cap.iface in names else names[0]
            if cap.on:
                cap.start()
        elif k == curses.KEY_DOWN:
            st["scroll"] += 1
        elif k == curses.KEY_UP:
            st["scroll"] -= 1
        elif k == curses.KEY_NPAGE:
            st["scroll"] += 10
        elif k == curses.KEY_PPAGE:
            st["scroll"] -= 10
        elif k == ord("s"):
            st["sort"] += 1
        elif k == ord("r"):
            dns.on = not dns.on
        elif k == ord("t"):
            st["proto"] = {"": "tcp", "tcp": "udp", "udp": ""}[st["proto"]]
        elif k == ord("w"):
            st["wild"] = not st["wild"]
        elif k == ord("/"):
            h, w = scr.getmaxyx()
            addstr(scr, h - 1, 0, (" filter> ").ljust(w), curses.A_REVERSE)
            curses.curs_set(1); curses.echo(); scr.timeout(-1)
            try:
                st["filter"] = scr.getstr(h - 1, 10, max(10, w - 12)).decode(errors="ignore").strip()
            except curses.error:
                pass
            curses.noecho(); curses.curs_set(0); scr.timeout(250)
        elif k == ord("p"):
            col.paused = not col.paused


def selftest():
    be = get_backend()
    print(f"OS:       {be.os['name']}  [{be.os['family']}]  backend={type(be).__name__}")
    for t in be.required + be.optional:
        p = shutil.which(t)
        print(f"tool:     {t:<9} {'OK  ' + p if p else 'MISSING (' + ('required' if t in be.required else 'optional') + ')'}")
    miss = [t for t in be.required + be.optional if not shutil.which(t)]
    if miss:
        print("install:  " + be.install_hint(miss))
    print(f"root:     {'yes' if os.geteuid() == 0 else 'no (process names / capture may be limited; capture uses sudo -n)'}")
    ifs, conns = be.read_interfaces(), be.read_connections()
    print(f"ifaces:   {len(ifs)} ({', '.join(sorted(ifs)[:8])})   default={be.default_iface()}")
    print(f"conns:    {len(conns)} parsed, {sum(1 for c in conns if c['pid'])} with a process, "
          f"{sum(1 for c in conns if c['bin'] or c['bout'])} with byte counters")
    if be.note:
        print(f"note:     {be.note}")
    return 0 if ifs else 1   # connections may legitimately be empty


def once(flt=""):
    print(f"OS: {get_backend().os['name']}")
    c = Collector()
    c.sample()
    time.sleep(1)
    c.sample()
    print("== Interfaces ==")
    for n, v in sorted(c.ifaces.items()):
        print(f"{n:<8}{v.get('ip', '-'):<16} in {hr(v['in_rate']):>10}  out {hr(v['out_rate']):>10}  total {hb(v['ibytes'])}/{hb(v['obytes'])}")
    print("== Top connections ==")
    st = dict(filter=flt, wild="--wild" in sys.argv)
    for r in sort_rows(apply_filter(list(c.conns.values()), st), "total")[:15]:
        print(f"{fit(r['proto'],5)}{fit(r['proc'],24)}{fit(r['conn'],52)}{fit(r['state'],13)} in {hb(r['bin']):>7} out {hb(r['bout']):>7}")


if __name__ == "__main__":
    be = get_backend()                       # detects the OS and exits cleanly if unsupported
    if "--selftest" in sys.argv:
        sys.exit(selftest())
    preflight(be)                            # exits with an install hint if a required tool is missing
    if "--once" in sys.argv:
        a = sys.argv
        once(a[a.index("--filter") + 1] if "--filter" in a and a.index("--filter") + 1 < len(a) else "")
    else:
        try:
            curses.wrapper(ui)
        except KeyboardInterrupt:
            pass
        finally:
            for c in CAPTURES:
                c.stop()
