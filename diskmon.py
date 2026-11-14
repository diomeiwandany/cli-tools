#!/usr/bin/env python3
"""diskmon - iptraf-ng style TUI for disk traffic on macOS.

Source: sudo fs_usage -w -f filesys
Usage:  sudo python3 diskmon.py [-i SECONDS]
Keys:   Tab/1/2/3 switch view, s cycle sort, p pause, +/- change interval, q quit
"""
import argparse
import collections
import curses
import os
import re
import subprocess
import sys
import threading
import time

READ_CALLS = {"read", "pread", "readv", "read_nocancel", "pread_nocancel",
              "RdData", "RdMeta", "PgIn", "page_in", "PAGE_IN", "pagein"}
WRITE_CALLS = {"write", "pwrite", "writev", "write_nocancel", "pwrite_nocancel",
               "WrData", "WrMeta", "PgOut", "page_out", "PAGE_OUT", "pageout"}
OPEN_CALLS = {"open", "open_nocancel", "openat", "open_dprotected", "creat"}
CLOSE_CALLS = {"close", "close_nocancel"}

LINE_RE = re.compile(
    r"^(?P<ts>\d\d:\d\d:\d\d(?:\.\d+)?)\s+(?P<call>\S+)\s+(?P<rest>.*?)"
    r"\s+(?P<dur>\d+\.\d+)(?:\s+W)?\s+(?P<proc>.+?)\.(?P<tid>\d+)\s*$"
)
FD_RE = re.compile(r"\bF=(\d+)")
B_RE = re.compile(r"\bB=0x([0-9a-fA-F]+)")
PATH_RE = re.compile(r"(/\S.*)$")

SELF = {"diskmon", "Python", "python3", "python", "fs_usage"}


def parse_line(line):
    """Return dict(ts, call, fd, nbytes, path, proc) or None."""
    m = LINE_RE.match(line.rstrip("\n"))
    if not m:
        return None
    rest = m.group("rest")
    fd = FD_RE.search(rest)
    b = B_RE.search(rest)
    rest_nofd = B_RE.sub("", FD_RE.sub("", rest))
    p = PATH_RE.search(rest_nofd)
    return {
        "ts": m.group("ts"),
        "call": m.group("call"),
        "fd": int(fd.group(1)) if fd else None,
        "nbytes": int(b.group(1), 16) if b else 0,
        "path": p.group(1).strip() if p else None,
        "proc": m.group("proc").strip(),
    }


class Counter:
    __slots__ = ("ops", "rbytes", "wbytes", "events")

    def __init__(self):
        self.ops = 0
        self.rbytes = 0
        self.wbytes = 0
        self.events = collections.deque()  # (t, rbytes, wbytes) for rate

    def add(self, now, r, w):
        self.ops += 1
        self.rbytes += r
        self.wbytes += w
        if r or w:
            self.events.append((now, r, w))
        while self.events and now - self.events[0][0] > 1.0:
            self.events.popleft()  # prune here so unseen views can't grow it

    def rates(self, now):
        while self.events and now - self.events[0][0] > 1.0:
            self.events.popleft()
        return (sum(e[1] for e in self.events), sum(e[2] for e in self.events))


class State:
    def __init__(self):
        self.lock = threading.Lock()
        self.procs = collections.defaultdict(Counter)
        self.paths = collections.defaultdict(Counter)
        self.total = Counter()
        self.log = collections.deque(maxlen=500)
        self.fdmap = {}  # (proc, fd) -> path
        self.start = time.time()
        self.paused = False
        self.lines_seen = 0
        self.error = ""

    def handle(self, ev, raw):
        if ev["proc"] in SELF or self.paused:
            return
        now = time.time()
        call, proc, fd = ev["call"], ev["proc"], ev["fd"]
        key = (proc, fd)
        path = ev["path"]
        if call in OPEN_CALLS and fd is not None and path:
            self.fdmap[key] = path
        elif call in CLOSE_CALLS and fd is not None:
            self.fdmap.pop(key, None)
        if not path and fd is not None:
            path = self.fdmap.get(key)
        r = ev["nbytes"] if call in READ_CALLS else 0
        w = ev["nbytes"] if call in WRITE_CALLS else 0
        with self.lock:
            self.lines_seen += 1
            self.procs[proc].add(now, r, w)
            self.total.add(now, r, w)
            if path or r or w:
                pk = path or "(unknown fd)"
                if pk in self.paths or len(self.paths) < 20000:  # bound memory
                    self.paths[pk].add(now, r, w)
            self.log.append(raw.rstrip("\n"))


def reader(state, proc_holder):
    try:
        p = subprocess.Popen(["fs_usage", "-w", "-f", "filesys"],
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             text=True, errors="replace")
    except OSError as e:
        state.error = f"cannot start fs_usage: {e}"
        return
    proc_holder.append(p)
    for line in p.stdout:
        ev = parse_line(line)
        if ev:
            state.handle(ev, line)
    err = (p.stderr.read() or "").strip().splitlines()
    state.error = f"fs_usage exited ({p.wait()}): {err[-1] if err else 'no output'}"


def human(n):
    n = float(n)
    for unit in ("B", "K", "M", "G", "T"):
        if n < 1024 or unit == "T":
            return f"{n:.0f}{unit}" if unit == "B" else f"{n:.1f}{unit}"
        n /= 1024


SORTS = ["rate", "total", "ops"]


def sort_key(mode, now):
    def k(item):
        c = item[1]
        r, w = c.rates(now)
        if mode == "rate":
            return r + w
        if mode == "total":
            return c.rbytes + c.wbytes
        return c.ops
    return k


def put(win, y, x, s, attr=0):
    h, w = win.getmaxyx()
    if y < 0 or y >= h or x >= w:
        return
    try:
        win.addnstr(y, x, s, max(0, w - x - 1), attr)
    except curses.error:
        pass


def draw_table(win, top, height, title, header, rows, sort_mode):
    put(win, top, 0, f" {title}  [sort: {sort_mode}] ", curses.A_REVERSE)
    put(win, top + 1, 0, header, curses.A_BOLD)
    for i, row in enumerate(rows[:max(0, height - 2)]):
        put(win, top + 2 + i, 0, row)


def draw(win, state, view, sort_mode, interval):
    win.erase()
    H, W = win.getmaxyx()
    now = time.time()
    log_h = max(5, H // 3)
    top_h = H - log_h - 1
    with state.lock:
        if view == 0:
            items = sorted(state.procs.items(), key=sort_key(sort_mode, now), reverse=True)
            rows = []
            for name, c in items:
                r, w = c.rates(now)
                rows.append(f"{name[:24]:<24} {c.ops:>9} {human(c.rbytes):>9} "
                            f"{human(c.wbytes):>9} {human(r) + '/s':>10} {human(w) + '/s':>10}")
            hdr = f"{'PROCESS':<24} {'OPS':>9} {'READ':>9} {'WRITTEN':>9} {'READ/s':>10} {'WRITE/s':>10}"
            draw_table(win, 0, top_h, "Per-process file I/O (syscalls, incl. cache hits)", hdr, rows, sort_mode)
        elif view == 1:
            items = sorted(state.paths.items(), key=sort_key(sort_mode, now), reverse=True)
            rows = []
            pw = max(20, W - 50)
            for path, c in items:
                r, w = c.rates(now)
                p = path if len(path) <= pw else "..." + path[-(pw - 3):]
                rows.append(f"{p:<{pw}} {human(c.rbytes):>9} {human(c.wbytes):>9} "
                            f"{human(r) + '/s':>10} {human(w) + '/s':>10}")
            hdr = f"{'PATH':<{pw}} {'READ':>9} {'WRITTEN':>9} {'READ/s':>10} {'WRITE/s':>10}"
            draw_table(win, 0, top_h, "Per-file I/O (syscalls, incl. cache hits)", hdr, rows, sort_mode)
        else:
            r, w = state.total.rates(now)
            up = int(now - state.start)
            t = state.total
            lines = [
                f"Uptime:            {up // 3600:02d}:{up % 3600 // 60:02d}:{up % 60:02d}",
                f"Total operations:  {t.ops}",
                f"Total read:        {human(t.rbytes)}",
                f"Total written:     {human(t.wbytes)}",
                f"Read rate:         {human(r)}/s",
                f"Write rate:        {human(w)}/s",
                f"Processes seen:    {len(state.procs)}",
                f"Files seen:        {len(state.paths)}",
                f"Paused:            {state.paused}",
            ]
            put(win, 0, 0, " General disk statistics ", curses.A_REVERSE)
            for i, l in enumerate(lines):
                put(win, 2 + i, 2, l)
        # log pane
        put(win, top_h, 0, " Recent events ", curses.A_REVERSE)
        tail = list(state.log)[-(log_h - 1):]
        for i, l in enumerate(tail):
            put(win, top_h + 1 + i, 0, l)
    msg = state.error or f"Tab/1-3 view  s sort  p pause  +/- interval ({interval:g}s)  q quit"
    put(win, H - 1, 0, msg, curses.A_BOLD if state.error else curses.A_DIM)
    win.refresh()


def ui(stdscr, state, interval):
    curses.curs_set(0)
    stdscr.timeout(int(interval * 1000))
    view, sort_idx = 0, 0
    while True:
        draw(stdscr, state, view, SORTS[sort_idx], interval)
        k = stdscr.getch()
        if k in (ord("q"), ord("Q")):
            return
        elif k == ord("\t"):
            view = (view + 1) % 3
        elif k in (ord("1"), ord("2"), ord("3")):
            view = k - ord("1")
        elif k == ord("s"):
            sort_idx = (sort_idx + 1) % len(SORTS)
        elif k == ord("p"):
            state.paused = not state.paused
        elif k in (ord("+"), ord("=")):
            interval = min(60.0, interval + (1.0 if interval >= 1 else 0.1))
            stdscr.timeout(int(interval * 1000))
        elif k in (ord("-"), ord("_")):
            interval = max(0.1, interval - (1.0 if interval > 1 else 0.1))
            stdscr.timeout(int(interval * 1000))


def main():
    ap = argparse.ArgumentParser(description="iptraf-ng style disk traffic monitor")
    ap.add_argument("-i", "--interval", type=float, default=1.0,
                    help="screen update interval in seconds (default 1, min 0.1)")
    args = ap.parse_args()
    interval = max(0.1, args.interval)
    if os.geteuid() != 0:
        sys.exit("diskmon needs root: sudo python3 diskmon.py")
    state = State()
    holder = []
    threading.Thread(target=reader, args=(state, holder), daemon=True).start()
    try:
        curses.wrapper(ui, state, interval)
    except KeyboardInterrupt:
        pass
    finally:
        for p in holder:
            p.terminate()


if __name__ == "__main__":
    main()
