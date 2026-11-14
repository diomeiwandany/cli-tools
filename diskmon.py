#!/usr/bin/env python3
"""diskmon - an iptraf-ng style file/disk I/O monitor for macOS and Linux (CLI modelled on netmon).

Stdlib only.
  macOS  : `fs_usage -w -f filesys` (needs root). Counts file-system calls, so cache hits are included.
  Linux  : per-process *disk* bytes from /proc/<pid>/io (root sees every process, a normal user only their
           own) plus, optionally, per-file events from `fatrace` (root; counts operations, no byte sizes).
Missing tools are offered for install via brew / apt / dnf / yum / pacman / zypper / apk.

    sudo python3 diskmon.py [--interval S] [--filter TEXT]
    sudo python3 diskmon.py --once [--duration S] [--filter TEXT]
    python3 diskmon.py --selftest  |  --install [-y]

Keys: 1-4 views | up/down/PgUp/PgDn scroll | s sort | / filter | p pause | +/- refresh | q quit
Filter terms: proc:NAME path:TEXT, or plain text (all terms must match).
"""
import argparse
import collections
import curses
import os
import platform
import re
import shutil
import subprocess
import sys
import threading
import time
import unicodedata

IS_MAC = platform.system() == "Darwin"
IS_LINUX = platform.system() == "Linux"

HIST = 120                        # seconds of throughput history
INTERVALS = [0.5, 1, 2, 5, 10]    # selectable refresh intervals (s)
SPARK = " ▁▂▃▄▅▆▇█"
MAX_PATHS = 20000                 # bound memory on busy machines
MAX_FDS = 50000
POLL = 0.5                        # Linux /proc polling period (s)

# Byte counts come from the read/write system calls (what applications asked for) plus mmap page-ins/outs.
# Disk-level lines (RdData/WrData/RdMeta/WrMeta, which carry D=) describe the same bytes again, so they are not counted.
READ_CALLS = {"read", "pread", "readv", "preadv", "read_nocancel", "pread_nocancel", "readv_nocancel",
              "PgIn", "page_in", "PAGE_IN", "pagein"}
WRITE_CALLS = {"write", "pwrite", "writev", "pwritev", "write_nocancel", "pwrite_nocancel", "writev_nocancel",
               "guarded_write_np", "guarded_pwrite_np", "guarded_writev_np",
               "PgOut", "page_out", "PAGE_OUT", "pageout"}
OPEN_CALLS = {"open", "open_nocancel", "openat", "open_dprotected", "creat"}
CLOSE_CALLS = {"close", "close_nocancel"}

LINE_RE = re.compile(
    r"^(?P<ts>\d\d:\d\d:\d\d(?:\.\d+)?)\s+(?P<call>\S+)\s+(?P<rest>.*?)"
    r"\s+(?P<dur>\d+\.\d+)(?:\s+W)?\s+(?P<proc>.+?)\.(?P<tid>\d+)\s*$"
)
FD_RE = re.compile(r"\bF=(\d+)")
B_RE = re.compile(r"\bB=0x([0-9a-fA-F]+)")
PATH_RE = re.compile(r"(/\S.*)$")
D_RE = re.compile(r"\bD=0x[0-9a-fA-F]+")
DEV_RE = re.compile(r"/dev/\S+(?=\s+/)")      # device node that precedes the real path on disk-level lines
FATRACE_RE = re.compile(r"^(?:(?P<ts>\d\d:\d\d:\d\d(?:\.\d+)?)\s+)?(?P<proc>.+?)\((?P<pid>\d+)\):\s+"
                        r"(?P<ev>\S+)\s+(?P<path>/.*)$")

SELF = {"diskmon", "Python", "python3", "python", "fs_usage"}   # macOS only: fs_usage reports no PIDs


# ------------------------------------------------------- package install assistance
PKG_ORDER = ["brew", "apt-get", "dnf", "yum", "pacman", "zypper", "apk"]
PKG_INSTALL = {"brew": ["install"], "apt-get": ["apt-get", "install", "-y"], "dnf": ["dnf", "install", "-y"],
               "yum": ["yum", "install", "-y"], "pacman": ["pacman", "-S", "--noconfirm"],
               "zypper": ["zypper", "--non-interactive", "install"], "apk": ["apk", "add"]}
PKG_MAP = {"fatrace": {m: "fatrace" for m in PKG_ORDER[1:]}}   # tool -> {package manager: package}


def find_brew():
    found = shutil.which("brew")
    if found:
        return found
    return next((p for p in ("/opt/homebrew/bin/brew", "/usr/local/bin/brew") if os.access(p, os.X_OK)), None)


def detect_pkg_manager():
    if IS_MAC:
        return "brew" if find_brew() else None
    return next((m for m in PKG_ORDER[1:] if shutil.which(m)), None)


def install_command(manager, packages):
    """Full command (with sudo when needed) that installs `packages`, or None if it can't be built."""
    if manager == "brew":
        cmd = [find_brew()] + PKG_INSTALL["brew"] + packages
        if os.geteuid() == 0 and os.environ.get("SUDO_USER"):    # Homebrew refuses to run as root
            cmd = ["sudo", "-u", os.environ["SUDO_USER"]] + cmd
        return cmd
    if not manager:
        return None
    if os.geteuid() != 0:
        if not shutil.which("sudo"):
            return None
        return ["sudo"] + PKG_INSTALL[manager] + packages
    return PKG_INSTALL[manager] + packages


def install_hint(tools):
    mgr = detect_pkg_manager()
    pkgs = sorted({PKG_MAP.get(t, {}).get(mgr, t) for t in tools})
    cmd = install_command(mgr, pkgs) if mgr else None
    return " ".join(cmd) if cmd else f"install {', '.join(tools)} with your package manager"


def offer_install(tools, assume_yes=False, required=True):
    """Offer to install missing tools. Never installs without asking (unless -y).
    Returns the tools that are still missing afterwards."""
    mgr = detect_pkg_manager()
    pkgs = []
    for t in tools:
        p = PKG_MAP.get(t, {}).get(mgr) if mgr else None
        if p and p not in pkgs:
            pkgs.append(p)
    cmd = install_command(mgr, pkgs) if pkgs else None
    print(f"diskmon: missing {'required' if required else 'optional'} tool(s): {', '.join(tools)}")
    if not cmd:
        if IS_MAC and not mgr:
            print("  Homebrew is not installed. Get it from https://brew.sh, then re-run.")
        else:
            print("  No supported package manager (or sudo) found; install them manually.")
        return list(tools)
    print("  install with: " + " ".join(cmd))
    if not assume_yes:
        if not (sys.stdin.isatty() and sys.stdout.isatty()):
            return list(tools)
        try:
            ans = input("  Run it now? [Y/n] " if required else "  Run it now? [y/N] ").strip().lower()
        except EOFError:
            return list(tools)
        if not (ans in ("y", "yes") or (required and ans == "")):
            return list(tools)
    if subprocess.run(cmd).returncode != 0:
        print("  install failed; try the command above manually.")
    return [t for t in tools if not shutil.which(t)]


# ------------------------------------------------------------------ parsing
def parse_line(line):
    """macOS fs_usage line -> dict(ts, call, fd, nbytes, path, proc) or None."""
    m = LINE_RE.match(line.rstrip("\n"))
    if not m:
        return None
    rest = m.group("rest")
    fd = FD_RE.search(rest)
    b = B_RE.search(rest)
    disk_level = bool(D_RE.search(rest))               # RdData/WrData...: duplicates a syscall's bytes
    clean = DEV_RE.sub(" ", D_RE.sub("", B_RE.sub("", FD_RE.sub("", rest))))
    p = PATH_RE.search(clean)
    path = re.sub(r"^/{2,}", "/", p.group(1).strip()) if p else None   # "[-2]//Users/x" -> "/Users/x"
    return {
        "ts": m.group("ts"),
        "call": re.sub(r"\[[^\]]*\]$", "", m.group("call")),           # "RdData[A]" -> "RdData"
        "fd": int(fd.group(1)) if fd else None,
        "nbytes": 0 if disk_level else (int(b.group(1), 16) if b else 0),
        "path": path,
        "proc": m.group("proc").lstrip(),   # keep a trailing space: it marks a truncated name
    }


def parse_fatrace(line):
    """Linux `fatrace -t` line, e.g. '12:00:01.123456 bash(1234): RO /etc/passwd' -> dict or None."""
    m = FATRACE_RE.match(line.rstrip("\n"))
    if not m:
        return None
    return dict(ts=m.group("ts") or "", proc=m.group("proc"), pid=int(m.group("pid")),
                ev=m.group("ev"), path=m.group("path"))


def read_proc_io(pid, proc_dir="/proc"):
    """/proc/<pid>/io -> (comm, syscalls, disk_read_bytes, disk_write_bytes) or None if unreadable."""
    try:
        with open(f"{proc_dir}/{pid}/io") as f:
            txt = f.read()
        with open(f"{proc_dir}/{pid}/comm") as f:
            comm = f.read().strip()
    except OSError:
        return None
    d = {}
    for line in txt.splitlines():
        k, _, v = line.partition(":")
        try:
            d[k] = int(v)
        except ValueError:
            pass
    return comm, d.get("syscr", 0) + d.get("syscw", 0), d.get("read_bytes", 0), d.get("write_bytes", 0)


def ps_command_names():
    """Base names of every running executable (full, untruncated process names)."""
    try:
        out = subprocess.run(["ps", "-axo", "comm="], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                             text=True, errors="replace", timeout=5).stdout
    except (OSError, subprocess.TimeoutExpired):
        return set()
    return {os.path.basename(line.strip()) for line in out.splitlines() if line.strip()}


def expand_names(truncated, names):
    """{truncated fs_usage name: full name}. fs_usage cuts names at 31 characters; a name is only expanded when
    exactly one running executable starts with it and the name is not itself a complete executable name."""
    mapping = {}
    for raw in truncated:
        if raw in names:
            continue
        cands = {n for n in names if n.startswith(raw)}
        if len(cands) == 1:
            mapping[raw] = cands.pop()
    return mapping


def parse_lsof(out):
    """`lsof -F pftn` output -> {fd: label} (path for files; "(PIPE)", "(IPv4)"... otherwise).
    An fd that different matching processes map to different things is ambiguous and left out."""
    recs, cur = [], {}
    for line in out.splitlines():
        if not line:
            continue
        tag, val = line[0], line[1:]
        if tag in "pf":
            if "fd" in cur and "name" in cur:
                recs.append(cur)
            cur = {} if tag == "p" else {"fd": int(val) if val.isdigit() else None}
        elif tag == "t":
            cur["type"] = val
        elif tag == "n":
            cur["name"] = val
    if "fd" in cur and "name" in cur:
        recs.append(cur)
    found = collections.defaultdict(set)
    for r in recs:
        if r["fd"] is not None:
            found[r["fd"]].add(r["name"] if r["name"].startswith("/") else f"({r.get('type') or 'other'})")
    return {fd: next(iter(v)) for fd, v in found.items() if len(v) == 1}


def lsof_lookup(proc, fds, timeout=5):
    """What the given fds of processes whose command starts with `proc` point to ({} on any failure)."""
    cmd = ["lsof", "-nP", "+c", "0", "-a", "-c", proc, "-d", ",".join(str(f) for f in sorted(fds)), "-F", "pftn"]
    try:
        out = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True,
                             errors="replace", timeout=timeout).stdout
    except (OSError, subprocess.TimeoutExpired):
        return {}
    return parse_lsof(out)


# ------------------------------------------------------------------ collector
class Counter:
    __slots__ = ("ops", "rbytes", "wbytes", "events")

    def __init__(self):
        self.ops = 0
        self.rbytes = 0
        self.wbytes = 0
        self.events = collections.deque()  # (t, rbytes, wbytes) for the 1 s rate window

    def add(self, now, r, w, ops=1):
        self.ops += ops
        self.rbytes += r
        self.wbytes += w
        if r or w:
            self.events.append((now, r, w))
        self._prune(now)   # prune here so views that don't render a counter can't grow it

    def _prune(self, now):
        while self.events and now - self.events[0][0] > 1.0:
            self.events.popleft()

    def rates(self, now):
        self._prune(now)
        return sum(e[1] for e in self.events), sum(e[2] for e in self.events)


class State:
    def __init__(self):
        self.lock = threading.Lock()
        self.procs = collections.defaultdict(Counter)
        self.paths = collections.defaultdict(Counter)
        self.total = Counter()
        self.log = collections.deque(maxlen=2000)     # (time, proc, path, raw line)
        self.hist = collections.deque(maxlen=HIST)    # (read/s, write/s), one sample per second
        self._ht = 0.0
        self.fdmap = {}                               # (proc, fd) -> path   (macOS)
        self.start = time.time()
        self.paused = False
        self.error = ""        # a collector died: shown in the bottom bar
        self.note = ""         # a limitation worth showing (e.g. not root)
        self.files_note = ""   # why the Files/Events views are empty (e.g. fatrace missing)
        self.file_bytes = IS_MAC   # False when per-file byte counts are unavailable (Linux)
        # macOS: reads/writes on fds opened before we started are resolved later with lsof
        self.names = {}            # truncated fs_usage name -> full name (macOS)
        self.trunc = set()         # truncated names waiting to be expanded
        self.name_tried = set()
        self.resolver_on = False
        self.resolved = {}         # (proc, fd) -> path/label found by lsof
        self.unk = {}              # (proc, fd) -> [ops, rbytes, wbytes] waiting for resolution
        self.pending = set()       # (proc, fd) to look up
        self.tried = set()         # (proc, fd) already looked up

    def _add_path(self, now, path, r, w, ops=1):
        if path in self.paths or len(self.paths) < MAX_PATHS:
            self.paths[path].add(now, r, w, ops)

    def handle(self, ev, raw):
        """macOS: one parsed fs_usage line."""
        if ev["proc"] in SELF or self.paused:
            return
        if self.resolver_on and ev["proc"] == "lsof":
            return      # our own resolver: counting it would feed back into more lookups
        now = time.time()
        call, raw_proc, fd = ev["call"], ev["proc"], ev["fd"]
        key = (raw_proc, fd)                         # fd bookkeeping and lsof use fs_usage's own name
        proc = self.names.get(raw_proc, raw_proc)    # counters and the display use the full name
        path = ev["path"]
        if call in OPEN_CALLS and fd is not None and path:
            if len(self.fdmap) > MAX_FDS:
                self.fdmap.clear()
            self.fdmap[key] = path
        elif call in CLOSE_CALLS and fd is not None:
            self.fdmap.pop(key, None)
            self.resolved.pop(key, None)
            self.tried.discard(key)
        if not path and fd is not None:
            path = self.fdmap.get(key) or self.resolved.get(key)
        r = ev["nbytes"] if call in READ_CALLS else 0
        w = ev["nbytes"] if call in WRITE_CALLS else 0
        unknown = not path and fd is not None and (r or w)
        with self.lock:
            if len(raw_proc) >= 31 and raw_proc not in self.names and raw_proc not in self.name_tried:
                self.trunc.add(raw_proc)
            self.procs[proc].add(now, r, w)
            self.total.add(now, r, w)
            if path or r or w:
                self._add_path(now, path or "(unknown fd)", r, w)
            if unknown and self.resolver_on:
                self._note_unknown(key, r, w)
            self.log.append((ev["ts"], proc, path or "", raw.rstrip("\n")))

    def _note_unknown(self, key, r, w):
        """Remember traffic on an unresolved fd and queue a lookup. Caller holds the lock."""
        u = self.unk.get(key)
        if u is None:
            if key in self.tried or len(self.unk) >= 2000:
                return
            u = self.unk[key] = [0, 0, 0]
            self.pending.add(key)
        u[0] += 1
        u[1] += r
        u[2] += w

    def take_truncated(self):
        with self.lock:
            todo, self.trunc = self.trunc, set()
            self.name_tried.update(todo)
            if len(self.name_tried) > 5000:
                self.name_tried.clear()
            return todo

    def apply_names(self, mapping):
        """Remember full names and fold the counters already collected under the truncated name into them."""
        with self.lock:
            for raw, full in mapping.items():
                self.names[raw] = full
                c = self.procs.pop(raw, None)
                if c:
                    t = self.procs[full]
                    t.ops += c.ops
                    t.rbytes += c.rbytes
                    t.wbytes += c.wbytes
                    t.events = collections.deque(sorted(list(t.events) + list(c.events)))

    def take_pending(self):
        """{proc: {fds}} still to look up; marks them as tried."""
        with self.lock:
            todo = collections.defaultdict(set)
            for proc, fd in self.pending:
                todo[proc].add(fd)
            self.tried.update(self.pending)
            self.pending.clear()
            if len(self.tried) > 20000:
                self.tried.clear()
            return todo

    def apply_resolved(self, proc, fds, mapping):
        """Record lsof results and move the bytes already counted under "(unknown fd)" to the real file."""
        now = time.time()
        with self.lock:
            if len(self.resolved) > MAX_FDS:
                self.resolved.clear()
            unk = self.paths.get("(unknown fd)")
            for fd in fds:
                key = (proc, fd)
                u = self.unk.pop(key, None)
                label = mapping.get(fd)
                if not label:
                    continue
                self.resolved[key] = label
                if u and unk:
                    unk.ops, unk.rbytes, unk.wbytes = (max(0, unk.ops - u[0]), max(0, unk.rbytes - u[1]),
                                                       max(0, unk.wbytes - u[2]))
                    self._add_path(now, label, u[1], u[2], u[0])
            if unk and not (unk.ops or unk.rbytes or unk.wbytes):
                self.paths.pop("(unknown fd)", None)      # nothing left in the bucket: drop the empty row

    def add_io(self, proc, ops, r, w):
        """Linux: a per-process delta from /proc."""
        if self.paused or not (ops or r or w):
            return
        now = time.time()
        with self.lock:
            self.procs[proc].add(now, r, w, ops)
            self.total.add(now, r, w, ops)

    def add_file_event(self, ev, raw):
        """Linux: one parsed fatrace line (operation counts only)."""
        if self.paused:
            return
        now = time.time()
        with self.lock:
            self._add_path(now, ev["path"], 0, 0)
            self.log.append((ev["ts"], ev["proc"], ev["path"], raw.rstrip("\n")))

    def tick(self, now):
        """Record one throughput sample per second (called from the UI loop). Caller holds the lock."""
        if now - self._ht >= 1.0:
            self._ht = now
            self.hist.append(self.total.rates(now))


class Source(threading.Thread):
    """A background data source feeding State."""

    def __init__(self, state):
        super().__init__(daemon=True)
        self.state, self.proc = state, None
        self._halt = threading.Event()

    def stop(self):
        self._halt.set()
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()


class CmdReader(Source):
    """Runs a command and feeds each output line to feed(); records why it stopped in state.error."""
    cmd = []

    def feed(self, line):
        raise NotImplementedError

    def run(self):
        try:
            self.proc = subprocess.Popen(self.cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                         text=True, errors="replace")
        except OSError as e:
            self.state.error = f"cannot start {self.cmd[0]}: {e}"
            return
        for line in self.proc.stdout:
            self.feed(line)
        err = (self.proc.stderr.read() or "").strip().splitlines()
        code = self.proc.wait()
        if not self._halt.is_set():
            self.state.error = f"{self.cmd[0]} exited ({code}): {err[-1] if err else 'no output'}"


class FsUsageReader(CmdReader):
    cmd = ["fs_usage", "-w", "-f", "filesys"]

    def feed(self, line):
        ev = parse_line(line)
        if ev:
            self.state.handle(ev, line)


class FatraceReader(CmdReader):
    cmd = ["fatrace", "-t"]

    def feed(self, line):
        ev = parse_fatrace(line)
        if ev and ev["pid"] != os.getpid():
            self.state.add_file_event(ev, line)


class NameResolver(Source):
    """macOS: expand names that fs_usage truncated to full process names, using `ps`."""

    def run(self):
        while not self._halt.wait(2.0):
            todo = self.state.take_truncated()
            if todo:
                mapping = expand_names(todo, ps_command_names())
                if mapping:
                    self.state.apply_names(mapping)


class FdResolver(Source):
    """macOS: fs_usage only prints a path when a file is opened; look up older fds with lsof, about once a second."""

    def run(self):
        while not self._halt.wait(1.0):
            for proc, fds in list(self.state.take_pending().items())[:15]:
                if self._halt.is_set():
                    return
                self.state.apply_resolved(proc, fds, lsof_lookup(proc, fds))


class ProcReader(Source):
    """Linux: poll /proc/<pid>/io and feed the per-process deltas of real disk I/O."""

    def __init__(self, state, proc_dir="/proc"):
        super().__init__(state)
        self.proc_dir = proc_dir

    def poll(self, prev, first):
        cur = {}
        me = str(os.getpid())
        try:
            pids = [p for p in os.listdir(self.proc_dir) if p.isdigit() and p != me]
        except OSError as e:
            self.state.error = f"cannot read {self.proc_dir}: {e}"
            return cur
        for pid in pids:
            snap = read_proc_io(pid, self.proc_dir)
            if not snap:
                continue
            cur[pid] = snap
            old = prev.get(pid)
            if old and old[0] == snap[0]:
                d = (snap[1] - old[1], snap[2] - old[2], snap[3] - old[3])
            elif not first:
                d = snap[1:]          # a process that started after us: all of it counts
            else:
                continue              # startup baseline
            if min(d) >= 0:
                self.state.add_io(snap[0], *d)
        return cur

    def run(self):
        prev, first = {}, True
        while not self._halt.is_set():
            prev = self.poll(prev, first)
            first = False
            self._halt.wait(POLL)


def make_sources(state):
    """Pick the data sources for this OS and record limitations on `state`."""
    if IS_MAC:
        srcs = [FsUsageReader(state), NameResolver(state)]
        if shutil.which("lsof"):
            state.resolver_on = True
            srcs.append(FdResolver(state))
        return srcs
    srcs = [ProcReader(state)]
    root = os.geteuid() == 0
    if not root:
        state.note = "not root: only your own processes are visible"
    if root and shutil.which("fatrace"):
        srcs.append(FatraceReader(state))
    elif not shutil.which("fatrace"):
        state.files_note = f"Per-file data needs fatrace (run as root): {install_hint(['fatrace'])}"
    else:
        state.files_note = "Per-file data needs root (fatrace): run with sudo"
    return srcs


# -------------------------------------------------------------------- helpers
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


def fit(s, n, right=False, keep_end=False):
    """Truncate/pad s to exactly n terminal cells (wide chars count 2). keep_end drops the left side instead."""
    s = str(s)
    if swidth(s) > n:
        out, w = "", 0
        for c in (reversed(s) if keep_end else s):
            if w + cw(c) > n - 1:
                break
            out, w = (c + out if keep_end else out + c), w + cw(c)
        s = "…" + out if keep_end else out + "…"
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


def spark(vals, width):
    vals = list(vals)[-width:]
    if not vals:
        return ""
    m = max(vals) or 1
    return "".join(SPARK[min(8, int(v / m * 8))] for v in vals)


# -------------------------------------------------------------- filter + sort
def parse_filter(text):
    terms = []
    for t in text.split():
        key, sep, val = t.partition(":")
        if sep and key in ("proc", "path") and val:
            terms.append((key, val.lower()))
        else:
            terms.append(("text", t.lower()))
    return terms


def match(proc, path, terms):
    for key, v in terms:
        if key == "proc" and v not in proc.lower():
            return False
        if key == "path" and v not in (path or "").lower():
            return False
        if key == "text" and v not in f"{proc} {path or ''}".lower():
            return False
    return True


SORTS = ["rate", "total", "ops", "name"]


def sort_items(items, mode, now):
    """items: [(name, Counter)] -> sorted list; name sorts A-Z, everything else biggest first."""
    if mode == "name":
        return sorted(items, key=lambda it: it[0].lower())

    def key(it):
        c = it[1]
        if mode == "rate":
            return sum(c.rates(now))
        if mode == "total":
            return c.rbytes + c.wbytes
        return c.ops
    return sorted(items, key=key, reverse=True)


# ---------------------------------------------------------------------- views
VIEWS = ["Processes", "Files", "Statistics", "Events"]


def view_processes(ctx):
    now, terms = ctx["now"], ctx["terms"]
    pw = max(20, min(44, ctx["w"] - 53))
    hdr = f"{'PROCESS':<{pw}}{'OPS':>10}{'READ':>10}{'WRITTEN':>10}{'READ/s':>11}{'WRITE/s':>11}"
    items = [(n, c) for n, c in ctx["procs"] if match(n, "", terms)]
    rows = []
    for n, c in sort_items(items, ctx["sort"], now):
        r, w = c.rates(now)
        rows.append(f"{fit(n, pw)}{c.ops:>10}{hb(c.rbytes):>10}{hb(c.wbytes):>10}{hr(r):>11}{hr(w):>11}")
    return hdr, rows


def view_files(ctx):
    now, terms, fb = ctx["now"], ctx["terms"], ctx["state"].file_bytes
    pw = max(20, ctx["w"] - 53)
    hdr = f"{'PATH':<{pw}}{'OPS':>9}{'READ':>10}{'WRITTEN':>10}{'READ/s':>11}{'WRITE/s':>11}"
    items = [(p, c) for p, c in ctx["paths"] if match("", p, terms)]
    mode = ctx["sort"] if fb or ctx["sort"] in ("ops", "name") else "ops"   # no bytes: rank by operations
    rows = []
    for p, c in sort_items(items, mode, now):
        if fb:
            r, w = c.rates(now)
            nums = f"{hb(c.rbytes):>10}{hb(c.wbytes):>10}{hr(r):>11}{hr(w):>11}"
        else:
            nums = f"{'-':>10}{'-':>10}{'-':>11}{'-':>11}"
        rows.append(f"{fit(p, pw, keep_end=True)}{c.ops:>9}{nums}")
    if ctx["state"].files_note and not rows:
        rows = [ctx["state"].files_note]
    return hdr, rows


def view_statistics(ctx):
    st, now = ctx["state"], ctx["now"]
    t = ctx["total"]
    up = int(now - st.start)
    r, w = ctx["rates"]
    sw = max(10, ctx["w"] - 30)
    hh = ctx["hist"]
    rows = [
        f"Uptime           {up // 3600:02d}:{up % 3600 // 60:02d}:{up % 60:02d}",
        f"Operations       {t[0]:,}",
        f"Total read       {hb(t[1])}",
        f"Total written    {hb(t[2])}",
        f"Processes seen   {ctx['n_procs']:,}",
        f"Files seen       {ctx['n_paths']:,}",
        "",
        f"READ  {spark([x[0] for x in hh], sw)}  {hr(r)}",
        f"WRITE {spark([x[1] for x in hh], sw)}  {hr(w)}",
    ]
    return "Throughput history (newest right); each line scaled to its own max", rows


def view_events(ctx):
    terms = ctx["terms"]
    hdr = "Recent events (newest at the bottom; Up scrolls back)" + ("   [PAUSED]" if ctx["state"].paused else "")
    rows = [raw for _, proc, path, raw in ctx["log"] if match(proc, path, terms)]
    if ctx["state"].files_note and not rows:
        rows = [ctx["state"].files_note]
    return hdr, rows


VIEW_BUILDERS = [view_processes, view_files, view_statistics, view_events]


# ------------------------------------------------------------------------ UI
def draw_topbar(scr, ctx):
    w, bar = ctx["w"], curses.A_REVERSE
    r, wr = ctx["rates"]
    if w >= 110:
        tabs = " ".join(f"[{i+1}]{n}" for i, n in enumerate(VIEWS))
        traffic = f"▼ READ {fit(hr(r), 10, right=True)}   ▲ WRITE {fit(hr(wr), 10, right=True)} "
    else:
        tabs = " ".join(f"[{i+1}]{n}" for i, n in enumerate(("Proc", "File", "Stats", "Evts")))
        traffic = f"▼{fit(hr(r), 9, right=True)} ▲{fit(hr(wr), 9, right=True)} "
    addstr(scr, 0, 0, fit(" diskmon  " + tabs, w), bar)
    addstr(scr, 0, max(0, w - swidth(traffic) - 1), traffic, bar | curses.A_BOLD)


def draw_body(scr, ctx, hdr, rows):
    h, w, st = ctx["h"], ctx["w"], ctx["ui"]
    addstr(scr, 2, 0, fit(hdr, w), curses.A_BOLD | curses.A_UNDERLINE)
    body = max(1, h - 5)
    if st["view"] == 3:    # live log: follow newest; Up scrolls back (negative offset)
        off = max(0, min(-st["scroll"], max(0, len(rows) - body)))
        st["scroll"] = -off
        top = max(0, len(rows) - body - off)
    else:
        st["scroll"] = max(0, min(st["scroll"], max(0, len(rows) - body)))
        top = st["scroll"]
    for i, r in enumerate(rows[top: top + body]):
        addstr(scr, 3 + i, 0, r)


BAR_MINW = [0, 5, 7, 4, max(len(x) for x in VIEWS), 9]


def bar_columns(ctx, nrows):
    """Bottom-bar columns: (current value, key, function, flexible?). Value is the upper line."""
    st, state = ctx["ui"], ctx["state"]
    view = st["view"]
    sortlbl = SORTS[st["sort"] % len(SORTS)] if view in (0, 1) else "-"
    return [
        (state.error or st["filter"] or state.note or "-", "/", "Filter", True),
        (sortlbl, "s", "Sort", False),
        ("PAUSED" if state.paused else "running", "p", "Pause", False),
        (f"{st['interval']:g}s", "+/-", "Refresh", False),
        (VIEWS[view], "1-4", "Views", False),
        (f"{nrows} rows", "q", "Quit", False),
    ], sortlbl


def draw_bottombar(scr, ctx, nrows):
    h, w, bar = ctx["h"], ctx["w"], curses.A_REVERSE
    cols, sortlbl = bar_columns(ctx, nrows)

    def build(br):
        return [(val, f"[{key}]" if br else key, fn, 0, flex) for val, key, fn, flex in cols]

    def widths(cs, fmax=40):
        base = [max(swidth(k) + 1 + swidth(fn), swidth(v), m) for (v, k, fn, _, _), m in zip(cs, BAR_MINW)]
        spare = (w - 1) - 2 - sum(b for b, c in zip(base, cs) if not c[4]) - (len(cs) - 1)
        return [min(fmax, max(spare, b)) if c[4] else b for b, c in zip(base, cs)]

    cs = build(True)
    if widths(cs)[0] < 12:
        cs = build(False)
    wd = widths(cs)
    xs = spread_pos(wd, w - 1)
    if h >= 8:
        addstr(scr, h - 2, 0, " " * w, bar)
        addstr(scr, h - 1, 0, " " * w, bar)
        for x, cwid, (val, k, fn, _, _) in zip(xs, wd, cs):
            addstr(scr, h - 2, x, fit(val, cwid), bar | curses.A_BOLD)
            addstr(scr, h - 1, x, k, bar | curses.A_BOLD)
            addstr(scr, h - 1, x + swidth(k), " " + fn, bar)
    else:
        flt = ctx["state"].error or ctx["ui"]["filter"] or "-"
        addstr(scr, h - 1, 0, fit(f" {nrows} rows | sort:{sortlbl} | filter:{flt}", w - 1), bar)


def build_ctx(scr, state, ui_state):
    h, w = scr.getmaxyx()
    now = time.time()
    with state.lock:
        state.tick(now)
        ctx = dict(
            h=h, w=w, now=now, state=state, ui=ui_state,
            procs=list(state.procs.items()) if ui_state["view"] == 0 else [],
            paths=list(state.paths.items()) if ui_state["view"] == 1 else [],
            log=list(state.log) if ui_state["view"] == 3 else [],
            hist=list(state.hist),
            total=(state.total.ops, state.total.rbytes, state.total.wbytes),
            rates=state.total.rates(now), n_procs=len(state.procs), n_paths=len(state.paths),
        )
    ctx["terms"] = parse_filter(ui_state["filter"])
    ctx["sort"] = SORTS[ui_state["sort"] % len(SORTS)]
    return ctx


def draw(scr, state, ui_state):
    scr.erase()
    ctx = build_ctx(scr, state, ui_state)
    hdr, rows = VIEW_BUILDERS[ui_state["view"]](ctx)
    draw_topbar(scr, ctx)
    draw_body(scr, ctx, hdr, rows)
    draw_bottombar(scr, ctx, len(rows))
    scr.refresh()


def ui(scr, state, interval, flt):
    curses.curs_set(0)
    st = dict(view=0, sort=0, scroll=0, filter=flt, interval=interval)
    scr.timeout(int(interval * 1000))
    while True:
        draw(scr, state, st)
        k = scr.getch()
        if k in (ord("q"), 27):
            return
        elif ord("1") <= k <= ord("4"):
            st.update(view=k - ord("1"), scroll=0, sort=0)
        elif k in (ord("+"), ord("="), ord("-"), ord("_")):
            near = min(range(len(INTERVALS)), key=lambda i: abs(INTERVALS[i] - st["interval"]))
            step = 1 if k in (ord("+"), ord("=")) else -1      # + = refresh more often
            st["interval"] = INTERVALS[max(0, min(len(INTERVALS) - 1, near - step))]
            scr.timeout(int(st["interval"] * 1000))
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
        elif k == ord("p"):
            state.paused = not state.paused
        elif k == ord("/"):
            h, w = scr.getmaxyx()
            addstr(scr, h - 1, 0, " filter> ".ljust(w), curses.A_REVERSE)
            curses.curs_set(1)
            curses.echo()
            scr.timeout(-1)
            try:
                st["filter"] = scr.getstr(h - 1, 9, max(10, w - 12)).decode(errors="ignore").strip()
            except curses.error:
                pass
            curses.noecho()
            curses.curs_set(0)
            scr.timeout(int(st["interval"] * 1000))
            st["scroll"] = 0


# ------------------------------------------------------- non-interactive modes
def os_name():
    if IS_MAC:
        return f"macOS {platform.mac_ver()[0]}".strip()
    try:
        with open("/etc/os-release") as f:
            for line in f:
                if line.startswith("PRETTY_NAME="):
                    return line.split("=", 1)[1].strip().strip('"')
    except OSError:
        pass
    return platform.system()


def preflight(assume_yes=False):
    """Make sure diskmon can run here, offering to install what is missing. Exits otherwise."""
    if not (IS_MAC or IS_LINUX):
        raise SystemExit(f"diskmon supports macOS and Linux (detected: {platform.system() or 'unknown'}).")
    root = os.geteuid() == 0
    if IS_MAC:
        if not shutil.which("fs_usage"):
            raise SystemExit("diskmon: fs_usage not found (it ships with macOS in /usr/bin).")
        if not root:
            raise SystemExit("diskmon needs root on macOS to read fs_usage: sudo python3 diskmon.py")
        return
    if not os.path.isdir("/proc/self"):
        raise SystemExit("diskmon: /proc is not available on this system.")
    if root and not shutil.which("fatrace"):
        offer_install(["fatrace"], assume_yes, False)       # optional: enables the per-file views


def collect(state, duration, startup=6.0):
    """Run the sources for `duration` seconds, counted from the first event (fs_usage takes a moment to attach)."""
    srcs = make_sources(state)
    for s in srcs:
        s.start()
    t0 = time.time()
    while not (state.total.ops or state.paths or state.error) and time.time() - t0 < startup:
        time.sleep(0.1)
    time.sleep(duration)
    for s in srcs:
        s.stop()


def selftest():
    print(f"OS:       {os_name()}  [{'macos' if IS_MAC else 'linux' if IS_LINUX else 'unsupported'}]")
    if not (IS_MAC or IS_LINUX):
        return 1
    root = os.geteuid() == 0
    ok = True
    if IS_MAC:
        p = shutil.which("fs_usage")
        print(f"tool:     fs_usage  {'OK  ' + p if p else 'MISSING (required)'}")
        ok = bool(p)
    else:
        p = shutil.which("fatrace")
        print(f"source:   /proc/<pid>/io  {'OK' if os.path.isdir('/proc/self') else 'MISSING (required)'}")
        print(f"tool:     fatrace   {'OK  ' + p if p else 'MISSING (optional: per-file views)'}")
        if not p:
            print(f"install:  {install_hint(['fatrace'])}")
        ok = os.path.isdir("/proc/self")
    print(f"root:     {'yes' if root else 'no' + (' (required to run)' if IS_MAC else ' (only your own processes are visible)')}")
    if not (ok and (root or IS_LINUX)):
        return 1
    st = State()
    collect(st, 3)
    print(f"capture:  {st.total.ops} operations, {len(st.procs)} processes, {len(st.paths)} paths in 3s"
          + (f"   ({st.error})" if st.error else ""))
    print(f"bytes:    read {hb(st.total.rbytes)}, written {hb(st.total.wbytes)}")
    return 0 if (st.total.ops or st.paths) else 1


def once(flt, duration):
    st = State()
    collect(st, max(1.0, duration))
    if st.error and not st.total.ops:
        raise SystemExit(f"diskmon: {st.error}")
    now = time.time()
    terms = parse_filter(flt)
    with st.lock:
        procs, paths = list(st.procs.items()), list(st.paths.items())
    print(f"== Processes (last {duration:g}s) ==")
    for n, c in sort_items([(n, c) for n, c in procs if match(n, "", terms)], "total", now)[:15]:
        print(f"{fit(n, 40)} ops {c.ops:>8}  read {hb(c.rbytes):>7}  written {hb(c.wbytes):>7}")
    print("== Top files ==")
    if st.files_note and not paths:
        print(st.files_note)
    for p, c in sort_items([(p, c) for p, c in paths if match("", p, terms)], "total" if st.file_bytes else "ops", now)[:15]:
        sizes = f"read {hb(c.rbytes):>7}  written {hb(c.wbytes):>7}" if st.file_bytes else f"ops {c.ops:>8}"
        print(f"{fit(p, 60, keep_end=True)} {sizes}")


def main():
    ap = argparse.ArgumentParser(description="iptraf-ng style file/disk I/O monitor for macOS and Linux")
    ap.add_argument("-i", "--interval", type=float, default=1.0, help="refresh interval in seconds (min 0.2, default 1)")
    ap.add_argument("--filter", default="", help="initial filter, e.g. 'proc:Safari path:Library'")
    ap.add_argument("--once", action="store_true", help="capture for --duration seconds, print a summary and exit")
    ap.add_argument("--duration", type=float, default=3.0, help="capture time for --once (default 3)")
    ap.add_argument("--selftest", action="store_true", help="check requirements and capture briefly")
    ap.add_argument("--install", action="store_true", help="offer to install missing optional tools")
    ap.add_argument("-y", "--yes", action="store_true", help="don't ask before installing packages")
    args = ap.parse_args()
    if args.selftest:
        sys.exit(selftest())
    if args.install:
        todo = [t for t in PKG_MAP if not shutil.which(t)] if IS_LINUX else []
        if not todo:
            print("diskmon: nothing to install." + (" (macOS needs only fs_usage, which ships with the OS)" if IS_MAC else ""))
            sys.exit(0)
        sys.exit(1 if offer_install(todo, args.yes, False) else 0)
    preflight(args.yes)
    if args.once:
        once(args.filter, args.duration)
        return
    state = State()
    srcs = make_sources(state)
    for s in srcs:
        s.start()
    try:
        curses.wrapper(ui, state, max(0.2, args.interval), args.filter)
    except KeyboardInterrupt:
        pass
    finally:
        for s in srcs:
            s.stop()


if __name__ == "__main__":
    main()
