# cli-tools

Standalone, stdlib-only Python 3 tools for **macOS and Linux**. Each one checks its requirements on start and
offers to install what is missing with the system package manager (brew, apt, dnf, yum, pacman, zypper, apk).
It always asks first; pass `-y` to skip the question.

| Tool | What it does | macOS | Linux |
|------|--------------|-------|-------|
| `netmon.py` | iptraf-ng style network monitor | `netstat`, `nettop` (built in); optional `tcpdump` | `ss` (iproute2); optional `tcpdump` |
| `diskmon.py` | iptraf-ng style file / disk I/O monitor (needs root on macOS) | `fs_usage` (built in), root | `/proc` (built in); optional `fatrace` + root for the per-file views |
| `jname` | DNS overview of a domain (A, AAAA, www, NS, MX, TXT, DMARC); POSIX `sh`; `-s SERVER` picks a resolver, `-t TYPE` limits the lookups, `-r` prints only the values (TXT unquoted and joined) for copying | `dig` (built in) | `dig` (`dnsutils` / `bind-utils` / `bind-tools`) |
| `usbbootmaker.py` | bootable USB drives from Windows / Linux images | `diskutil`, `hdiutil` (built in); `wimlib` for Windows ISOs with files over 4 GB | `lsblk`, `parted`, `mkfs.vfat`/`mkfs.exfat`, `mount`/`umount`, `blockdev`; `wimlib` |

## Checking and installing requirements

```
python3 netmon.py --selftest        # what is present / missing
python3 netmon.py --install [-y]    # offer to install missing tools

python3 diskmon.py --selftest
python3 diskmon.py --install [-y]

python3 usbbootmaker.py --check [-y]

./jname example.com                 # asks to install dig if it is missing (-y: don't ask)
./jname -r -t dmarc example.com | pbcopy   # just the DMARC value, ready to paste (xclip / wl-copy on Linux)
```

Homebrew itself is never installed automatically; if it is missing the tools point to https://brew.sh.

## Notes

- `diskmon` measures different things per OS: on macOS it counts file-system calls (cache hits included), on
  Linux it reports real disk bytes per process from `/proc/<pid>/io`, and per-file operation counts (no byte
  sizes) when `fatrace` is available. Without root on Linux only your own processes are visible.
- `usbbootmaker` checks every tool it may need when it starts (menu or write) and offers to install all the missing ones with a single prompt; saying no is fine, and it still stops before touching a drive if a tool that write needs is missing. `--check` shows the same thing without starting.
- `usbbootmaker` writes to disks and needs root; it re-launches itself with sudo and asks you to type the
  device name before erasing anything. Use `--dry-run` to see what would happen.
