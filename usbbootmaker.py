#!/usr/bin/env python3
"""USB Boot Maker - interactive command-line version (macOS and Linux).

Creates bootable USB drives from Windows installer ISOs and from Linux / raw
disk images (.iso, .img, .gz), with SHA-256 checks. Raw writes are also verified
by reading the device back; Windows file copies are not read back.

    python3 usbbootmaker.py            # interactive menu
    python3 usbbootmaker.py --list     # list removable drives and exit
    python3 usbbootmaker.py --check    # check tools, offer to install missing ones
    python3 usbbootmaker.py --help

Standard library only. Writing to drives needs root; the script re-launches
itself through sudo when you start a write. On start it checks every external
tool it may need and offers to install the missing ones in one go (brew on
macOS; apt-get, dnf, yum, pacman, zypper or apk on Linux).
"""

import argparse
import glob
import gzip
import hashlib
import json
import os
import platform
import plistlib
import shutil
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Tuple

try:  # tab completion for typed paths
    import readline  # noqa: F401
except ImportError:  # pragma: no cover
    readline = None

VERSION = "1.0"
IS_MAC = platform.system() == "Darwin"
IS_LINUX = platform.system() == "Linux"

BUFFER_SIZE = 4 * 1024 * 1024
SECTOR = 4096
FAT32_MAX_FILE = 4 * 1024 ** 3 - 1
IMAGE_EXTENSIONS = (".iso", ".img", ".gz")


# --------------------------------------------------------------------------- #
# Terminal helpers
# --------------------------------------------------------------------------- #
USE_COLOR = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None


def c(text: str, code: str) -> str:
    return f"\033[{code}m{text}\033[0m" if USE_COLOR else text


def bold(t): return c(t, "1")
def dim(t): return c(t, "2")
def red(t): return c(t, "31")
def green(t): return c(t, "32")
def yellow(t): return c(t, "33")
def cyan(t): return c(t, "36")


def info(msg): print(f"{cyan('•')} {msg}")
def ok(msg): print(f"{green('✔')} {msg}")
def warn(msg): print(f"{yellow('!')} {msg}")
def err(msg): print(f"{red('✘')} {msg}", file=sys.stderr)


class UserAbort(Exception):
    """Raised when the user cancels an operation."""


class CliError(Exception):
    """A user-facing error (no traceback)."""


def human_size(n: float) -> str:
    units = ["B", "KB", "MB", "GB", "TB", "PB"]
    i = 0
    while n >= 1000 and i < len(units) - 1:
        n /= 1000
        i += 1
    return f"{n:.0f} {units[i]}" if i == 0 else f"{n:.2f} {units[i]}"


def ask(prompt: str, default: Optional[str] = None) -> str:
    suffix = f" [{default}]" if default else ""
    try:
        value = input(f"{bold('?')} {prompt}{suffix}: ").strip()
    except EOFError:
        raise UserAbort()
    return value or (default or "")


def ask_yes_no(prompt: str, default: bool = True) -> bool:
    hint = "Y/n" if default else "y/N"
    while True:
        value = ask(f"{prompt} ({hint})").lower()
        if not value:
            return default
        if value in ("y", "yes"):
            return True
        if value in ("n", "no"):
            return False


class Progress:
    """Single-line progress bar with speed and ETA."""

    def __init__(self, label: str, total: int):
        self.label = label
        self.total = max(total, 0)
        self.start = time.time()
        self.last = 0.0
        self.enabled = sys.stdout.isatty()

    def update(self, done: int, force: bool = False) -> None:
        now = time.time()
        if not force and now - self.last < 0.1:
            return
        self.last = now
        if not self.enabled:
            return
        elapsed = max(now - self.start, 1e-6)
        speed = done / elapsed
        frac = min(done / self.total, 1.0) if self.total else 0.0
        width = 28
        filled = int(width * frac)
        bar = "█" * filled + "░" * (width - filled)
        eta = f" ETA {int((self.total - done) / speed)}s" if speed > 0 and self.total > done else ""
        line = f"\r{self.label:<22} {bar} {frac * 100:5.1f}%  {human_size(done)}/{human_size(self.total)}  {human_size(speed)}/s{eta}   "
        sys.stdout.write(line)
        sys.stdout.flush()

    def finish(self) -> None:
        self.update(self.total, force=True)
        if self.enabled:
            sys.stdout.write("\n")
            sys.stdout.flush()


# --------------------------------------------------------------------------- #
# Image tools (same rules as the macOS app's ImageTools)
# --------------------------------------------------------------------------- #
def is_hybrid_linux_image(path: str) -> bool:
    """ISO 9660 image with an MBR boot signature and boot code ("isohybrid")."""
    try:
        with open(path, "rb") as f:
            head = f.read(512)
            if len(head) != 512:
                return False
            if head[510:512] != b"\x55\xaa" or not any(head[:446]):
                return False
            f.seek(0x8001)
            return f.read(5) == b"CD001"
    except OSError:
        return False


def is_gzip_path(path: str) -> bool:
    return path.lower().endswith(".gz")


def is_valid_sha256(value: str) -> bool:
    return len(value) == 64 and all(ch in "0123456789abcdefABCDEF" for ch in value)


def expected_sha256_for(path: str) -> Optional[str]:
    for suffix in (".sha256", ".sha256sum", ".SHA256"):
        side = path + suffix
        try:
            with open(side, "r", encoding="utf-8", errors="ignore") as f:
                for token in f.read().split():
                    if is_valid_sha256(token):
                        return token.lower()
        except OSError:
            continue
    return None


def sha256_file(path: str, progress: Optional[Callable[[int, int], None]] = None) -> str:
    total = os.path.getsize(path)
    h = hashlib.sha256()
    done = 0
    with open(path, "rb") as f:
        while True:
            chunk = f.read(BUFFER_SIZE)
            if not chunk:
                break
            h.update(chunk)
            done += len(chunk)
            if progress:
                progress(done, total)
    return h.hexdigest()


def classify_image(path: str) -> str:
    """Returns 'directory', 'gzip', 'raw-image', 'linux', 'windows' or 'unknown'."""
    if os.path.isdir(path):
        return "directory"
    if not os.path.isfile(path):
        return "unknown"
    lower = path.lower()
    if lower.endswith(".gz"):
        return "gzip"
    if lower.endswith(".img"):
        return "raw-image"
    if is_hybrid_linux_image(path):
        return "linux"
    if lower.endswith(".iso"):
        return "windows"
    return "unknown"


def uses_raw_write(kind: str, mode: str) -> bool:
    if mode == "linux":
        return True
    if mode == "windows":
        return False
    return kind in ("linux", "raw-image", "gzip")


def copy_image(path: str, fd: int, sector: int = SECTOR,
               progress: Optional[Callable[[int, int], bool]] = None) -> Tuple[str, int]:
    """Stream an image (raw or .gz) into fd, padding the last block to `sector`.

    Returns (sha256 of the image data, exact byte length of the image data).
    `progress(done, total)` returns False to stop; UserAbort is raised then.
    """
    file_size = os.path.getsize(path)
    total = file_size
    opener = open
    if is_gzip_path(path):
        # The last 4 bytes of a gzip file hold the uncompressed size modulo 2**32 (display only).
        if file_size > 4:
            with open(path, "rb") as f:
                f.seek(-4, os.SEEK_END)
                isize = int.from_bytes(f.read(4), "little")
            if isize:
                total = isize
        opener = gzip.open

    digest = hashlib.sha256()
    exact = 0
    if progress and not progress(0, total):
        raise UserAbort()
    with opener(path, "rb") as src:
        while True:
            chunk = src.read(BUFFER_SIZE)
            if not chunk:
                break
            digest.update(chunk)
            exact += len(chunk)
            if len(chunk) % sector:
                # raw devices need whole sectors
                chunk = chunk + b"\0" * (sector - len(chunk) % sector)
            view = memoryview(chunk)
            offset = 0
            while offset < len(view):
                offset += os.write(fd, view[offset:])
            if progress and not progress(exact, max(total, exact)):
                raise UserAbort()
    return digest.hexdigest(), exact


def verify_fd(fd: int, length: int, expected: str, sector: int = SECTOR,
              progress: Optional[Callable[[int, int], bool]] = None) -> bool:
    """Re-read `length` bytes from fd and compare their SHA-256 with `expected`."""
    os.lseek(fd, 0, os.SEEK_SET)
    if hasattr(os, "posix_fadvise"):
        try:
            os.posix_fadvise(fd, 0, 0, os.POSIX_FADV_DONTNEED)
        except OSError:
            pass
    digest = hashlib.sha256()
    remaining = length
    done = 0
    while remaining > 0:
        wanted = min(BUFFER_SIZE, (remaining + sector - 1) // sector * sector)
        data = os.read(fd, wanted)
        if not data:
            return False  # device shorter than the image
        usable = data[:remaining]
        digest.update(usable)
        remaining -= len(usable)
        done += len(usable)
        if progress and not progress(done, length):
            raise UserAbort()
    return digest.hexdigest() == expected


# --------------------------------------------------------------------------- #
# Drives
# --------------------------------------------------------------------------- #
@dataclass
class Drive:
    ident: str                 # disk4 / sdb (or the path of a plain file used as a fake device)
    path: str                  # /dev/disk4, /dev/sdb
    size: int
    vendor: str = ""
    model: str = ""
    mounts: List[str] = field(default_factory=list)
    external: bool = True
    system: bool = False
    is_file: bool = False

    @property
    def raw_path(self) -> str:
        if IS_MAC and self.path.startswith("/dev/disk"):
            return "/dev/r" + self.path[len("/dev/"):]
        return self.path

    @property
    def title(self) -> str:
        name = f"{self.vendor} {self.model}".strip() or "Unknown device"
        return name

    def fingerprint(self) -> Tuple[str, int, str]:
        return (self.ident, self.size, self.title)


def parse_macos_drives(list_plist: dict, info_by_id: Dict[str, dict]) -> List[Drive]:
    """Build Drive objects from `diskutil list -plist` and per-disk `diskutil info -plist` data."""
    drives: List[Drive] = []
    entries = {e.get("DeviceIdentifier"): e for e in list_plist.get("AllDisksAndPartitions", [])}
    for ident in list_plist.get("WholeDisks", []):
        info_d = info_by_id.get(ident, {})
        entry = entries.get(ident, {})
        mounts = [p["MountPoint"] for p in entry.get("Partitions", []) if p.get("MountPoint")]
        mounts += [v["MountPoint"] for v in entry.get("APFSVolumes", []) if v.get("MountPoint")]
        if entry.get("MountPoint"):
            mounts.append(entry["MountPoint"])
        name = info_d.get("MediaName", "") or ""
        drives.append(Drive(
            ident=ident,
            path=info_d.get("DeviceNode", f"/dev/{ident}"),
            size=int(info_d.get("TotalSize", info_d.get("Size", entry.get("Size", 0))) or 0),
            vendor="",
            model=name,
            mounts=mounts,
            external=not info_d.get("Internal", False),
            system=bool(info_d.get("SystemImage", False)) or any(m == "/" or m.startswith("/System/Volumes") for m in mounts),
        ))
    return drives


def parse_linux_drives(lsblk_json: str) -> List[Drive]:
    data = json.loads(lsblk_json)
    drives: List[Drive] = []

    def collect_mounts(node: dict) -> List[str]:
        found = []
        mp = node.get("mountpoints") or [node.get("mountpoint")]
        found.extend(m for m in mp if m)
        for child in node.get("children", []) or []:
            found.extend(collect_mounts(child))
        return found

    for node in data.get("blockdevices", []):
        if node.get("type") != "disk":
            continue
        name = node["name"]
        mounts = collect_mounts(node)
        removable = str(node.get("rm")) in ("1", "True", "true") or node.get("rm") is True
        hotplug = str(node.get("hotplug")) in ("1", "True", "true") or node.get("hotplug") is True
        # hotplug alone is not trusted: some internal SATA/AHCI ports report it
        external = (node.get("tran") == "usb") or removable or (hotplug and node.get("tran") not in ("sata", "ata", "nvme"))
        system = any(m == "/" or m.startswith("/boot") for m in mounts)
        drives.append(Drive(
            ident=name,
            path=node.get("path") or f"/dev/{name}",
            size=int(node.get("size") or 0),
            vendor=(node.get("vendor") or "").strip(),
            model=(node.get("model") or "").strip(),
            mounts=mounts,
            external=external,
            system=system,
        ))
    return drives


def run(cmd: List[str], dry_run: bool = False, check: bool = True,
        capture: bool = True) -> subprocess.CompletedProcess:
    if dry_run:
        print(dim("  [dry-run] " + " ".join(cmd)))
        return subprocess.CompletedProcess(cmd, 0, b"", b"")
    try:
        result = subprocess.run(cmd, capture_output=capture)
    except FileNotFoundError:
        raise CliError(f"The command '{cmd[0]}' was not found. Install it and try again.")
    if check and result.returncode != 0:
        detail = (result.stderr or b"").decode(errors="ignore").strip() if capture else ""
        raise CliError(f"Command failed: {' '.join(cmd)}\n{detail}")
    return result


def scan_drives(include_internal: bool = False) -> List[Drive]:
    """Find drives that can be written to. Internal and system disks are skipped by default."""
    drives: List[Drive] = []
    if IS_MAC:
        listing = run(["diskutil", "list", "-plist"] + ([] if include_internal else ["external", "physical"])).stdout
        list_plist = plistlib.loads(listing)
        infos = {}
        for ident in list_plist.get("WholeDisks", []):
            try:
                infos[ident] = plistlib.loads(run(["diskutil", "info", "-plist", ident]).stdout)
            except Exception:
                infos[ident] = {}
        drives = parse_macos_drives(list_plist, infos)
    elif IS_LINUX:
        ensure_linux_tools(["lsblk"])
        out = run([find_tool("lsblk") or "lsblk", "-J", "-b", "-p", "-o",
                   "NAME,PATH,SIZE,MODEL,VENDOR,TRAN,RM,HOTPLUG,TYPE,MOUNTPOINTS"], check=False)
        if out.returncode != 0:  # older util-linux has no MOUNTPOINTS column
            out = run([find_tool("lsblk") or "lsblk", "-J", "-b", "-p", "-o",
                       "NAME,PATH,SIZE,MODEL,VENDOR,TRAN,RM,HOTPLUG,TYPE,MOUNTPOINT"])
        drives = parse_linux_drives(out.stdout.decode())
        for d in drives:  # -p makes names absolute; keep a short identifier
            d.ident = os.path.basename(d.ident)
    else:
        raise CliError("Only macOS and Linux are supported.")
    return [d for d in drives
            if not d.system and (include_internal or d.external) and d.size > 0]


def drive_from_file(path: str) -> Drive:
    """A regular file used as a fake device (for tests and dry runs)."""
    return Drive(ident=path, path=path, size=os.path.getsize(path) if os.path.exists(path) else 0,
                 model="Regular file", is_file=True)


def print_drives(drives: List[Drive]) -> None:
    if not drives:
        warn("No removable drives found. Plug in a USB drive and scan again.")
        return
    print(bold(f"  {'#':<3} {'Device':<10} {'Size':>10}  {'Name':<32} Mounted"))
    for i, d in enumerate(drives, 1):
        mounts = ", ".join(os.path.basename(m) or m for m in d.mounts) or "-"
        flag = red(" [internal]") if not d.external else ""
        print(f"  {i:<3} {d.ident:<10} {human_size(d.size):>10}  {d.title[:32]:<32} {mounts}{flag}")


def image_is_on_drive(image: str, drive: Drive) -> bool:
    real = os.path.realpath(image)
    for mount in drive.mounts:
        mount = os.path.realpath(mount)  # /var -> /private/var on macOS, bind mounts, symlinks
        if mount != "/" and (real == mount or real.startswith(mount.rstrip("/") + "/")):
            return True
    return False


# --------------------------------------------------------------------------- #
# Write flows
# --------------------------------------------------------------------------- #
@dataclass
class Options:
    mode: str = "auto"          # auto | windows | linux
    fs: str = "FAT32"           # FAT32 | ExFAT (Windows installers)
    verify: bool = True
    eject: bool = True
    label: str = "USBBOOT"
    checksum: str = ""
    dry_run: bool = False


def unmount_drive(drive: Drive, dry_run: bool = False) -> None:
    if drive.is_file:
        return
    if IS_MAC:
        run(["diskutil", "unmountDisk", "force", drive.path], dry_run, check=False)
    else:
        for part in sorted(glob.glob(drive.path + "*"), reverse=True):
            run([find_tool("umount") or "umount", part], dry_run, check=False)


def eject_drive(drive: Drive, dry_run: bool = False) -> None:
    if drive.is_file:
        return
    if IS_MAC:
        run(["diskutil", "eject", drive.path], dry_run, check=False)
    else:
        run(["sync"], dry_run, check=False)
        run([find_tool("eject") or "eject", drive.path], dry_run, check=False)


def write_raw(image: str, drive: Drive, opts: Options) -> None:
    """Write an image byte-for-byte to the whole device, then verify it."""
    info(f"Raw write: {os.path.basename(image)} -> {drive.path}")
    if opts.dry_run:
        unmount_drive(drive, True)
        print(dim(f"  [dry-run] write {human_size(os.path.getsize(image))} to {drive.raw_path}"
                  + (" and verify" if opts.verify else "")))
        return
    unmount_drive(drive)
    flags = os.O_RDWR
    if drive.is_file:
        flags |= os.O_CREAT | os.O_TRUNC
    try:
        fd = os.open(drive.raw_path, flags, 0o600)
    except OSError as e:
        raise CliError(f"Can't open {drive.raw_path}: {e.strerror}. Run as root and make sure nothing uses the drive.")
    try:
        if hasattr(fcntl_module(), "F_NOCACHE") and not drive.is_file:
            fcntl_module().fcntl(fd, fcntl_module().F_NOCACHE, 1)
        bar = Progress("Writing image", 0)

        def on_progress(done: int, total: int) -> bool:
            bar.total = total
            bar.update(done)
            return True

        try:
            digest, length = copy_image(image, fd, SECTOR, on_progress)
        except OSError as e:
            raise CliError(f"Writing to {drive.raw_path} failed: {e.strerror or e}. "
                           "The drive is too small or was removed; its contents are now incomplete.")
        finally:
            bar.finish()
        os.fsync(fd)
        full = getattr(fcntl_module(), "F_FULLFSYNC", None)
        if full is not None and not drive.is_file:
            try:
                fcntl_module().fcntl(fd, full)
            except OSError:
                pass
        if not IS_MAC and not drive.is_file:
            run([find_tool("blockdev") or "blockdev", "--flushbufs", drive.path], check=False)
        ok(f"Written {human_size(length)}.")
        if opts.verify:
            vbar = Progress("Verifying", length)

            def on_verify(done: int, total: int) -> bool:
                vbar.update(done)
                return True

            try:
                good = verify_fd(fd, length, digest, SECTOR, on_verify)
            finally:
                vbar.finish()
            if not good:
                raise CliError("Verification FAILED: the data on the device does not match the image. "
                               "The drive may be faulty.")
            ok("Verification passed: the device data matches the image.")
    finally:
        os.close(fd)


def fcntl_module():
    import fcntl  # imported lazily: unavailable on non-POSIX systems
    return fcntl


def mount_iso(image: str, dry_run: bool = False) -> Tuple[str, Callable[[], None]]:
    """Mount an ISO read-only. Returns (mount point, cleanup function)."""
    if dry_run:
        print(dim(f"  [dry-run] mount {image} read-only"))
        return "/dry-run/iso", lambda: None
    if IS_MAC:
        out = run(["hdiutil", "attach", "-readonly", "-noverify", "-noautofsck", "-noautoopen", "-plist", image]).stdout
        entities = plistlib.loads(out).get("system-entities", [])
        mount = next((e.get("mount-point") for e in entities if e.get("mount-point")), None)
        dev = next((e.get("dev-entry") for e in entities if e.get("dev-entry")), None)
        if not mount:
            raise CliError("The ISO was attached but has no mount point.")

        def cleanup() -> None:
            if dev and run(["hdiutil", "detach", dev], check=False).returncode != 0:
                run(["hdiutil", "detach", dev, "-force"], check=False)
        return mount, cleanup
    tmp = tempfile.mkdtemp(prefix="ubm-iso-")
    run([find_tool("mount") or "mount", "-o", "loop,ro", image, tmp])

    def cleanup_linux() -> None:
        run([find_tool("umount") or "umount", tmp], check=False)
        try:
            os.rmdir(tmp)
        except OSError:
            pass
    return tmp, cleanup_linux


def partition_node(dev: str, number: int = 1) -> str:
    """/dev/sdb -> /dev/sdb1, /dev/nvme0n1 -> /dev/nvme0n1p1"""
    return f"{dev}p{number}" if dev[-1].isdigit() else f"{dev}{number}"


def format_drive(drive: Drive, opts: Options) -> Tuple[str, Callable[[], None]]:
    """Create an MBR table with one partition. Returns (mount point, cleanup)."""
    label = opts.label.upper()[:11] or "USBBOOT"
    if opts.dry_run:
        print(dim(f"  [dry-run] format {drive.path} as MBR + {opts.fs} '{label}'"))
        return "/dry-run/target", lambda: None
    if IS_MAC:
        run(["diskutil", "eraseDisk", "ExFAT" if opts.fs == "ExFAT" else "FAT32", label, "MBR", drive.path])
        # The volume may be mounted as "LABEL 1" if the name is taken: ask diskutil instead of guessing.
        try:
            part = plistlib.loads(run(["diskutil", "info", "-plist", drive.path + "s1"]).stdout)
            mount = part.get("MountPoint") or ""
        except Exception:
            mount = ""
        if not mount:
            raise CliError("The drive was formatted but its new volume is not mounted. Nothing was copied.")
        return mount, lambda: None
    unmount_drive(drive)
    run([find_tool("parted") or "parted", "-s", drive.path, "mklabel", "msdos", "mkpart", "primary",
         "fat32" if opts.fs == "FAT32" else "ntfs", "1MiB", "100%", "set", "1", "boot", "on"])
    run([find_tool("udevadm") or "udevadm", "settle"], check=False)
    part = partition_node(drive.path)
    if opts.fs == "ExFAT":
        run([find_tool("mkfs.exfat") or "mkfs.exfat", "-n", label, part])
    else:
        run([find_tool("mkfs.vfat") or "mkfs.vfat", "-F", "32", "-n", label, part])
    mount = tempfile.mkdtemp(prefix="ubm-usb-")
    run([find_tool("mount") or "mount", part, mount])

    def cleanup() -> None:
        run(["sync"], check=False)
        run([find_tool("umount") or "umount", mount], check=False)
        try:
            os.rmdir(mount)
        except OSError:
            pass
    return mount, cleanup


def list_files(root: str) -> List[Tuple[str, int]]:
    files = []
    for base, _dirs, names in os.walk(root):
        for n in names:
            full = os.path.join(base, n)
            if os.path.isfile(full):
                files.append((full, os.path.getsize(full)))
    return files


def copy_file(src: str, dst: str, on_bytes: Callable[[int], None]) -> None:
    os.makedirs(os.path.dirname(dst), exist_ok=True)
    with open(src, "rb") as fin, open(dst, "wb") as fout:
        while True:
            chunk = fin.read(BUFFER_SIZE)
            if not chunk:
                break
            fout.write(chunk)
            on_bytes(len(chunk))
        fout.flush()
        os.fsync(fout.fileno())


EXTRA_TOOL_DIRS = ["/opt/homebrew/bin", "/usr/local/bin", "/opt/local/bin", "/usr/bin"]


def find_wimlib() -> Optional[str]:
    """Path of the wimlib command-line tool, or None. Also looks where Homebrew installs it."""
    for name in ("wimlib-imagex", "wimsplit"):
        found = shutil.which(name)
        if found:
            return found
        for directory in EXTRA_TOOL_DIRS:
            candidate = os.path.join(directory, name)
            if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
                return candidate
    return None


def wimlib_install_command() -> Optional[List[str]]:
    """The command that installs wimlib on this system (run as the right user), or None."""
    if IS_MAC:
        brew = shutil.which("brew") or next((os.path.join(d, "brew") for d in EXTRA_TOOL_DIRS[:2]
                                             if os.path.isfile(os.path.join(d, "brew"))), None)
        if not brew:
            return None
        cmd = [brew, "install", "wimlib"]
        # Homebrew refuses to run as root: go back to the user who started sudo.
        if hasattr(os, "geteuid") and os.geteuid() == 0 and os.environ.get("SUDO_USER"):
            cmd = ["sudo", "-u", os.environ["SUDO_USER"]] + cmd
        return cmd
    prefix = [] if os.geteuid() == 0 else (["sudo"] if shutil.which("sudo") else None)
    if prefix is None:
        return None
    managers = [
        ("apt-get", ["apt-get", "install", "-y", "wimtools"]),
        ("dnf", ["dnf", "install", "-y", "wimlib-utils"]),
        ("yum", ["yum", "install", "-y", "wimlib-utils"]),
        ("pacman", ["pacman", "-S", "--noconfirm", "wimlib"]),
        ("zypper", ["zypper", "--non-interactive", "install", "wimlib"]),
        ("apk", ["apk", "add", "wimlib"]),
    ]
    for binary, cmd in managers:
        if shutil.which(binary):
            return prefix + cmd
    return None


# Linux system tools -> the package that provides them, per package manager.
SBIN_DIRS = ["/sbin", "/usr/sbin"]
LINUX_PACKAGES: Dict[str, Dict[str, str]] = {
    "lsblk":      {"apt-get": "util-linux", "dnf": "util-linux", "yum": "util-linux", "pacman": "util-linux",
                   "zypper": "util-linux", "apk": "lsblk"},
    "blockdev":   {"apt-get": "util-linux", "dnf": "util-linux", "yum": "util-linux", "pacman": "util-linux",
                   "zypper": "util-linux", "apk": "util-linux-misc"},
    "mount":      {"apt-get": "mount", "dnf": "util-linux", "yum": "util-linux", "pacman": "util-linux",
                   "zypper": "util-linux", "apk": "mount"},
    "umount":     {"apt-get": "mount", "dnf": "util-linux", "yum": "util-linux", "pacman": "util-linux",
                   "zypper": "util-linux", "apk": "mount"},
    "parted":     {"apt-get": "parted", "dnf": "parted", "yum": "parted", "pacman": "parted",
                   "zypper": "parted", "apk": "parted"},
    "mkfs.vfat":  {"apt-get": "dosfstools", "dnf": "dosfstools", "yum": "dosfstools", "pacman": "dosfstools",
                   "zypper": "dosfstools", "apk": "dosfstools"},
    "mkfs.exfat": {"apt-get": "exfatprogs", "dnf": "exfatprogs", "yum": "exfatprogs", "pacman": "exfatprogs",
                   "zypper": "exfatprogs", "apk": "exfatprogs"},
    "wimlib-imagex": {"apt-get": "wimtools", "dnf": "wimlib-utils", "yum": "wimlib-utils", "pacman": "wimlib",
                      "zypper": "wimlib", "apk": "wimlib"},
}
PACKAGE_MANAGER_ORDER = ["apt-get", "dnf", "yum", "pacman", "zypper", "apk"]
PACKAGE_INSTALL_ARGS = {
    "apt-get": ["apt-get", "install", "-y"],
    "dnf": ["dnf", "install", "-y"],
    "yum": ["yum", "install", "-y"],
    "pacman": ["pacman", "-S", "--noconfirm"],
    "zypper": ["zypper", "--non-interactive", "install"],
    "apk": ["apk", "add"],
}


def find_tool(name: str) -> Optional[str]:
    """Locate a command, including sbin directories that regular users often don't have in PATH."""
    found = shutil.which(name)
    if found:
        return found
    for directory in SBIN_DIRS + EXTRA_TOOL_DIRS:
        candidate = os.path.join(directory, name)
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    return None


def detect_package_manager() -> Optional[str]:
    return next((m for m in PACKAGE_MANAGER_ORDER if shutil.which(m)), None)


def required_linux_tools(kind_is_raw: bool, fs: str = "FAT32") -> List[str]:
    """Commands needed on Linux: always the drive scan; then raw write or Windows formatting."""
    tools = ["lsblk", "umount"]
    if kind_is_raw:
        tools += ["blockdev"]
    else:
        tools += ["mount", "parted", "mkfs.exfat" if fs == "ExFAT" else "mkfs.vfat"]
    return tools


def missing_tools(tools: List[str]) -> List[str]:
    return [t for t in tools if (find_wimlib() if t == "wimlib-imagex" else find_tool(t)) is None]


def linux_packages_for(tools: List[str], manager: str) -> List[str]:
    packages: List[str] = []
    for tool in tools:
        package = LINUX_PACKAGES.get(tool, {}).get(manager)
        if package and package not in packages:
            packages.append(package)
    return packages


def ensure_linux_tools(tools: List[str], assume_yes: bool = False, dry_run: bool = False) -> None:
    """Make sure the Linux commands we call exist *before* a drive is touched; offer to install them."""
    missing = missing_tools(tools)
    if not missing:
        return
    warn("These commands are required but not installed: " + ", ".join(missing))
    manager = detect_package_manager()
    packages = linux_packages_for(missing, manager) if manager else []
    if not manager or not packages:
        raise CliError("No supported package manager found. Install these manually: " + ", ".join(missing))
    prefix: List[str] = []
    if os.geteuid() != 0:
        if not shutil.which("sudo"):
            raise CliError("Administrator rights (sudo) are needed to install: " + ", ".join(packages))
        prefix = ["sudo"]
    command = prefix + PACKAGE_INSTALL_ARGS[manager] + packages
    print(f"  Install command: {' '.join(command)}")
    if dry_run:
        print(dim("  [dry-run] would install the packages above"))
        return
    if not assume_yes and not ask_yes_no("Install them now?", True):
        raise CliError("Required tools are missing. Install: " + " ".join(packages))
    info("Installing…")
    result = subprocess.run(command)
    still_missing = missing_tools(tools)
    if result.returncode != 0 or still_missing:
        raise CliError("Installing the packages failed or the tools are still missing: "
                       + ", ".join(still_missing or missing)
                       + f"\n  Try manually: {' '.join(command)}")
    ok("Required tools installed.")


def needs_wim_split(image: str, fs: str) -> bool:
    """Whether writing this Windows image to `fs` may require splitting install.wim."""
    if fs != "FAT32":
        return False
    if os.path.isdir(image):
        for name in ("install.wim", "Install.wim", "INSTALL.WIM"):
            wim = os.path.join(image, "sources", name)
            if os.path.isfile(wim):
                return os.path.getsize(wim) > FAT32_MAX_FILE
        return False
    # For an ISO the exact size of install.wim is only known once it is mounted. An ISO over 4 GB
    # nearly always means a big install.wim, so make sure the tool is there before anything starts.
    return os.path.isfile(image) and os.path.getsize(image) > FAT32_MAX_FILE


def ensure_wimlib(assume_yes: bool = False, dry_run: bool = False) -> str:
    """Make sure wimlib is installed *before* any drive is touched. Installs it after asking."""
    found = find_wimlib()
    if found:
        return found
    command = wimlib_install_command()
    manual = "brew install wimlib" if IS_MAC else "sudo apt install wimtools   (or your distro's wimlib package)"
    warn("wimlib is required to split install.wim (larger than 4 GB) for FAT32, but it is not installed.")
    if command is None:
        if IS_MAC:
            raise CliError("Homebrew was not found. Install it from https://brew.sh, then run: brew install wimlib\n"
                           "  Or choose the ExFAT filesystem in Options (no splitting needed).")
        raise CliError(f"No supported package manager found. Install wimlib manually: {manual}\n"
                       "  Or choose the ExFAT filesystem in Options (no splitting needed).")
    print(f"  Install command: {' '.join(command)}")
    if dry_run:
        print(dim("  [dry-run] would install wimlib"))
        return "wimlib-imagex"
    if not assume_yes and not ask_yes_no("Install wimlib now?", True):
        raise CliError(f"wimlib is required. Install it with: {manual}\n"
                       "  Or choose the ExFAT filesystem in Options (no splitting needed).")
    info("Installing wimlib…")
    result = subprocess.run(command)
    found = find_wimlib()
    if result.returncode != 0 or not found:
        raise CliError(f"Installing wimlib failed. Install it manually: {manual}")
    ok(f"wimlib installed: {found}")
    return found


# Every external tool this platform may need, and what it is for.
TOOL_PURPOSE = {
    "diskutil": "list, erase and eject drives (ships with macOS)",
    "hdiutil": "mount ISO images (ships with macOS)",
    "lsblk": "list drives",
    "umount": "unmount drives and images",
    "mount": "mount ISO images and the new volume",
    "blockdev": "flush the device after a raw write",
    "parted": "partition the USB drive for Windows installers",
    "mkfs.vfat": "format FAT32",
    "mkfs.exfat": "format exFAT",
    "wimlib-imagex": "split an install.wim over 4 GB so it fits FAT32",
}


def all_tools() -> List[str]:
    """Every external tool usbbootmaker may call on this platform, whatever the image type."""
    if IS_MAC:
        return ["diskutil", "hdiutil", "wimlib-imagex"]
    return ["lsblk", "umount", "blockdev", "mount", "parted", "mkfs.vfat", "mkfs.exfat", "wimlib-imagex"]


def install_command_for(tools: List[str]) -> Optional[List[str]]:
    """The single command (with sudo when needed) that installs `tools` here, or None if it can't be built."""
    if IS_MAC:
        return wimlib_install_command() if "wimlib-imagex" in tools else None   # the rest ships with macOS
    manager = detect_package_manager()
    packages = linux_packages_for(tools, manager) if manager else []
    if not packages:
        return None
    prefix: List[str] = [] if os.geteuid() == 0 else (["sudo"] if shutil.which("sudo") else None)
    if prefix is None:
        return None
    return prefix + PACKAGE_INSTALL_ARGS[manager] + packages


def ensure_all_tools(assume_yes: bool = False, dry_run: bool = False) -> List[str]:
    """Check every tool this platform may need and offer to install the missing ones with ONE prompt.

    Called at startup so nothing runs out half way through writing a drive. Declining (or a failed install) is
    not fatal here: the write-time checks still stop before a drive is touched. Returns the tools still missing."""
    missing = missing_tools(all_tools())
    if not missing:
        return []
    system = [t for t in missing if t in ("diskutil", "hdiutil")]
    installable = [t for t in missing if t not in system]
    if system:
        warn("These macOS system tools are missing: " + ", ".join(system) + ". Check your PATH or reinstall them.")
    if not installable:
        return missing
    warn("These tools are not installed yet:")
    for tool in installable:
        print(f"    {tool:<14} {dim(TOOL_PURPOSE.get(tool, ''))}")
    command = install_command_for(installable)
    if command is None:
        if IS_MAC:
            warn("Homebrew was not found. Install it from https://brew.sh, then run: brew install wimlib")
        elif detect_package_manager() is None:
            warn("No supported package manager found. Install them yourself: " + ", ".join(installable))
        else:
            warn("Administrator rights (sudo) are needed to install them: " + ", ".join(installable))
        return missing
    print(f"  Install command: {' '.join(command)}")
    if dry_run:
        print(dim("  [dry-run] would install the tools above"))
        return missing
    if not assume_yes:
        if not sys.stdin.isatty():
            warn("Not a terminal, so nothing was installed. Run the command above yourself, or use --check -y.")
            return missing
        if not ask_yes_no("Install them now?", True):
            warn("Skipped. Anything that needs these tools will stop with an error until they are installed.")
            return missing
    info("Installing…")
    result = subprocess.run(command)
    still = missing_tools(installable) + system
    if result.returncode != 0 or still:
        warn("The install did not finish: " + ", ".join(still or installable) + f"\n  Try manually: {' '.join(command)}")
    else:
        ok("All required tools are installed.")
    return still


def check_deps(assume_yes: bool = False) -> int:
    """`--check`: report every tool this platform may need and offer to install what is missing."""
    info(f"Platform: {platform.system()} {platform.release()}")
    if not (IS_MAC or IS_LINUX):
        raise CliError("Only macOS and Linux are supported.")
    for tool in all_tools():
        found = find_wimlib() if tool == "wimlib-imagex" else find_tool(tool)
        print(f"  {tool:<14} {green('OK ') + dim(found) if found else yellow('MISSING')}")
    still = ensure_all_tools(assume_yes)
    if still:
        warn("Still missing: " + ", ".join(still))
        return 1
    ok("All required tools are available.")
    return 0


def preflight(image: str, opts: "Options", assume_yes: bool = False) -> None:
    """Checks that must pass before anything is erased or written (and before any sudo restart)."""
    kind = classify_image(image)
    if kind in ("unknown",):
        return
    raw = uses_raw_write(kind, opts.mode)
    if IS_LINUX:
        ensure_linux_tools(required_linux_tools(raw, opts.fs), assume_yes, opts.dry_run)
    if raw:
        return
    if needs_wim_split(image, opts.fs):
        ensure_wimlib(assume_yes, opts.dry_run)


def split_wim(src: str, dst_dir: str, dry_run: bool = False) -> None:
    tool = find_wimlib()
    if not tool and not dry_run:
        raise CliError("wimlib is not installed (it should have been installed before starting). "
                       "Run again so it can be installed, or choose ExFAT.")
    dst = os.path.join(dst_dir, "sources", "install.swm")
    if not dry_run:
        os.makedirs(os.path.dirname(dst), exist_ok=True)
    cmd = [tool or "wimlib-imagex", "split", src, dst, "3800"]
    run(cmd, dry_run, capture=False)


def write_windows(image: str, drive: Drive, opts: Options) -> None:
    info(f"Windows installer: {os.path.basename(image)} -> {drive.path} ({opts.fs})")
    if drive.is_file:
        raise CliError("Windows installers need a real drive; a plain file can't be formatted.")
    source = image
    cleanup_iso: Callable[[], None] = lambda: None
    if not os.path.isdir(image):
        source, cleanup_iso = mount_iso(image, opts.dry_run)
        ok(f"ISO mounted at {source}")
    cleanup_target: Callable[[], None] = lambda: None
    try:
        files = [] if opts.dry_run else list_files(source)
        if not opts.dry_run:
            if not any(os.path.basename(f).lower() in ("bootmgr", "setup.exe") or "/sources/" in f.lower()
                       for f, _ in files) and opts.mode != "windows":
                raise CliError("This doesn't look like a Windows installer (no bootmgr / sources folder), "
                               "so copying it would give an unbootable drive. If it is a Linux image, use "
                               "--mode linux; if you are sure it is Windows, use --mode windows. "
                               "Nothing was changed.")
        unmount_drive(drive, opts.dry_run)
        target, cleanup_target = format_drive(drive, opts)
        if not opts.dry_run and not os.path.isdir(target):
            raise CliError(f"The formatted volume was not found at {target}.")
        total = sum(size for _, size in files)
        bar = Progress("Copying files", total)
        done = 0

        def on_bytes(n: int) -> None:
            nonlocal done
            done += n
            bar.update(done)

        try:
            for src, size in files:
                rel = os.path.relpath(src, source)
                dst = os.path.join(target, rel)
                if opts.fs == "FAT32" and size > FAT32_MAX_FILE:
                    if rel.lower().replace("\\", "/").endswith("sources/install.wim"):
                        bar.finish()
                        info("install.wim is over 4 GB: splitting it for FAT32...")
                        split_wim(src, target, opts.dry_run)
                        done += size
                        continue
                    raise CliError(f"{rel} is larger than 4 GB and can't be stored on FAT32. Choose ExFAT.")
                copy_file(src, dst, on_bytes)
        finally:
            bar.finish()
        if opts.dry_run:
            print(dim(f"  [dry-run] copy all files from {source} to {target}"))
        ok("All files copied.")
    finally:
        cleanup_iso()
        cleanup_target()
    if opts.eject:
        eject_drive(drive, opts.dry_run)


def confirm_device(drive: Drive, assume_yes: bool) -> None:
    print()
    print(red(bold("  ALL DATA ON THIS DEVICE WILL BE PERMANENTLY ERASED")))
    print(f"  Device : {bold(drive.ident)}  ({drive.path})")
    print(f"  Name   : {drive.title}")
    print(f"  Size   : {human_size(drive.size)}")
    if drive.mounts:
        print(f"  Volumes: {', '.join(drive.mounts)}")
    if assume_yes:
        return
    typed = ask(f"Type the device name ({drive.ident}) to confirm, or press Enter to cancel")
    if typed != drive.ident:
        raise UserAbort()


def do_write(image: str, drive: Drive, opts: Options, assume_yes: bool = False) -> None:
    kind = classify_image(image)
    if kind in ("unknown",):
        raise CliError(f"Can't use {image}: not an image file or folder.")
    if image_is_on_drive(image, drive):
        raise CliError("The image is stored on the target drive. Choose another drive or copy the image elsewhere.")
    if drive.is_file and os.path.exists(drive.path) and os.path.exists(image) and os.path.samefile(image, drive.path):
        raise CliError("The image and the target device are the same file; writing would destroy the image.")
    if drive.system:
        raise CliError("Refusing to write to the system disk.")
    raw = uses_raw_write(kind, opts.mode)
    if raw and kind == "directory":
        raise CliError("Linux/raw mode needs an image file, not a folder.")
    if raw and not drive.is_file and os.path.isfile(image) and drive.size:
        # For .gz this is the compressed size, i.e. a lower bound of what will be written.
        if os.path.getsize(image) > drive.size:
            raise CliError(f"The image ({human_size(os.path.getsize(image))}) is larger than the drive "
                           f"({human_size(drive.size)}).")
    if opts.checksum:
        if not is_valid_sha256(opts.checksum):
            raise CliError("The checksum is not a valid SHA-256 value (64 hexadecimal characters).")
        if os.path.isfile(image):
            bar = Progress("Checking checksum", os.path.getsize(image))
            actual = sha256_file(image, lambda d, t: bar.update(d))
            bar.finish()
            if actual != opts.checksum.lower():
                raise CliError("The image checksum does not match the expected value. "
                               "The image may be corrupted or tampered with.")
            ok("Checksum matches.")
    preflight(image, opts, assume_yes)
    confirm_device(drive, assume_yes)
    started = time.time()
    if raw:
        write_raw(image, drive, opts)
        if opts.eject:
            eject_drive(drive, opts.dry_run)
    else:
        write_windows(image, drive, opts)
    ok(f"Done in {time.time() - started:.0f}s. You can remove the drive safely.")


# --------------------------------------------------------------------------- #
# Choosing an image
# --------------------------------------------------------------------------- #
def native_file_dialog() -> Optional[str]:
    """Open the system file picker. Returns a path, or None if unavailable/cancelled."""
    try:
        if IS_MAC:
            script = ('POSIX path of (choose file with prompt "Choose an ISO / disk image" '
                      'of type {"iso","img","gz","public.iso-image"})')
            out = subprocess.run(["osascript", "-e", script], capture_output=True, text=True)
            return out.stdout.strip() or None if out.returncode == 0 else None
        for tool, args in (("zenity", ["--file-selection", "--title=Choose an ISO / disk image"]),
                           ("kdialog", ["--getopenfilename", os.path.expanduser("~"), "*.iso *.img *.gz"])):
            if shutil.which(tool):
                out = subprocess.run([tool] + args, capture_output=True, text=True)
                return out.stdout.strip() or None if out.returncode == 0 else None
    except OSError:
        pass
    return None


def reveal_in_file_manager(path: str) -> None:
    target = path if os.path.isdir(path) else os.path.dirname(path) or "."
    opener = "open" if IS_MAC else "xdg-open"
    if shutil.which(opener):
        subprocess.Popen([opener, target], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    else:
        warn(f"Can't open a file manager here. Folder: {target}")


def terminal_browser(start: Optional[str] = None) -> Optional[str]:
    """Simple numbered file browser. Returns a chosen file path or None."""
    downloads = os.path.expanduser("~/Downloads")
    cwd = os.path.abspath(start or (downloads if os.path.isdir(downloads) else os.path.expanduser("~")))
    page = 0
    per_page = 15
    while True:
        try:
            names = sorted(os.listdir(cwd), key=str.lower)
        except OSError as e:
            warn(f"Can't read {cwd}: {e.strerror}")
            cwd = os.path.dirname(cwd)
            continue
        dirs = [n for n in names if not n.startswith(".") and os.path.isdir(os.path.join(cwd, n))]
        files = [n for n in names if n.lower().endswith(IMAGE_EXTENSIONS) and os.path.isfile(os.path.join(cwd, n))]
        entries = [("dir", d) for d in dirs] + [("file", f) for f in files]
        pages = max(1, (len(entries) + per_page - 1) // per_page)
        page = min(page, pages - 1)
        print()
        print(bold(f"  {cwd}"))
        for i, (kind, name) in enumerate(entries[page * per_page:(page + 1) * per_page], page * per_page + 1):
            if kind == "dir":
                print(f"  {i:>3}  {cyan(name + '/')}")
            else:
                size = human_size(os.path.getsize(os.path.join(cwd, name)))
                print(f"  {i:>3}  {green(name)}  {dim(size)}")
        if not entries:
            print(dim("  (no folders or .iso/.img/.gz files here)"))
        print(dim(f"  page {page + 1}/{pages}   number = open/select   .. = up   ~ = home   n/p = next/prev page"
                  "   o = open this folder in the file manager   b = back"))
        choice = ask("Browse").strip()
        if choice in ("b", "q", ""):
            return None
        if choice == "..":
            cwd, page = os.path.dirname(cwd) or "/", 0
        elif choice == "~":
            cwd, page = os.path.expanduser("~"), 0
        elif choice == "n":
            page = min(page + 1, pages - 1)
        elif choice == "p":
            page = max(page - 1, 0)
        elif choice == "o":
            reveal_in_file_manager(cwd)
        elif choice.isdigit() and 1 <= int(choice) <= len(entries):
            kind, name = entries[int(choice) - 1]
            if kind == "dir":
                cwd, page = os.path.join(cwd, name), 0
            else:
                return os.path.join(cwd, name)
        elif os.path.exists(os.path.expanduser(choice)):
            path = os.path.abspath(os.path.expanduser(choice))
            if os.path.isdir(path):
                cwd, page = path, 0
            else:
                return path
        else:
            warn("Not a valid choice.")


def typed_path() -> Optional[str]:
    if readline:
        try:
            def completer(text, state):
                matches = glob.glob(os.path.expanduser(text) + "*")
                matches = [m + "/" if os.path.isdir(m) else m for m in matches]
                return matches[state] if state < len(matches) else None
            readline.set_completer_delims(" \t\n")
            readline.set_completer(completer)
            readline.parse_and_bind("bind ^I rl_complete" if IS_MAC else "tab: complete")
        except Exception:
            pass
    value = ask("Path to the ISO / image (Tab completes, empty = cancel)")
    value = value.strip("'\" ").replace("\\ ", " ")   # drag-and-drop from Terminal escapes spaces
    return os.path.abspath(os.path.expanduser(value)) if value else None


# --------------------------------------------------------------------------- #
# Interactive session
# --------------------------------------------------------------------------- #
KIND_TEXT = {
    "linux": "Linux hybrid ISO (raw write)",
    "windows": "Windows installer ISO (format + copy files)",
    "raw-image": "Raw disk image (raw write)",
    "gzip": "Compressed disk image (raw write)",
    "directory": "Folder with Windows installer files",
    "unknown": "Unknown file type",
}


class Session:
    def __init__(self, include_internal: bool = False, opts: Optional[Options] = None):
        self.image: Optional[str] = None
        self.drive: Optional[Drive] = None
        self.drives: List[Drive] = []
        self.include_internal = include_internal
        self.opts = opts or Options()

    # -- display ---------------------------------------------------------- #
    def header(self) -> None:
        print()
        print(bold(cyan("  USB Boot Maker")) + dim(f"  CLI v{VERSION}  ({platform.system()})"))
        print(dim("  " + "─" * 58))
        if self.image:
            kind = classify_image(self.image)
            size = human_size(os.path.getsize(self.image)) if os.path.isfile(self.image) else ""
            print(f"  Image : {bold(os.path.basename(self.image))}  {dim(size)}")
            print(f"          {dim(KIND_TEXT.get(kind, kind))}")
        else:
            print(f"  Image : {dim('not selected')}")
        if self.drive:
            print(f"  Drive : {bold(self.drive.ident)}  {self.drive.title}  {dim(human_size(self.drive.size))}")
        else:
            print(f"  Drive : {dim('not selected')}")
        o = self.opts
        print(dim(f"  Mode: {o.mode}   FS: {o.fs}   Verify: {'on' if o.verify else 'off'}   "
                  f"Eject: {'on' if o.eject else 'off'}" + ("   DRY-RUN" if o.dry_run else "")))
        print(dim("  " + "─" * 58))

    def menu(self) -> str:
        items = [
            ("1", "Choose ISO / image (file dialog, browser or typed path)"),
            ("2", "Scan USB drives"),
            ("3", "Select drive"),
            ("4", "Options (mode, filesystem, verify, eject, checksum)"),
            ("5", "Open the image's folder in the file manager"),
            ("6", "Start writing"),
            ("q", "Quit"),
        ]
        for key, text in items:
            print(f"  {bold(key)}  {text}")
        return ask("Select").lower()

    # -- actions ---------------------------------------------------------- #
    def choose_image(self) -> None:
        print(f"  {bold('a')}  Open file dialog")
        print(f"  {bold('b')}  Browse folders in the terminal")
        print(f"  {bold('c')}  Type / paste a path")
        how = ask("How", "a" if (IS_MAC or shutil.which("zenity") or shutil.which("kdialog")) else "b").lower()
        path = None
        if how == "a":
            path = native_file_dialog()
            if path is None:
                warn("No file chosen (or no file dialog available). Falling back to the terminal browser.")
                path = terminal_browser()
        elif how == "b":
            path = terminal_browser()
        elif how == "c":
            path = typed_path()
        if not path:
            return
        kind = classify_image(path)
        if kind == "unknown":
            err("That is not an image file (.iso / .img / .gz) or a folder.")
            return
        self.image = path
        self.opts.checksum = ""
        ok(f"Selected: {path}")
        info(KIND_TEXT.get(kind, kind) + (f", {human_size(os.path.getsize(path))}" if os.path.isfile(path) else ""))
        self.offer_checksum()

    def offer_checksum(self) -> None:
        if not self.image or not os.path.isfile(self.image):
            return
        found = expected_sha256_for(self.image)
        if found:
            info(f"Found a checksum file next to the image: {found[:16]}…")
            if ask_yes_no("Use it to check the image before writing?", True):
                self.opts.checksum = found
            return
        value = ask("Paste the expected SHA-256 to check the image before writing (Enter to skip)")
        if value:
            if is_valid_sha256(value):
                self.opts.checksum = value.lower()
            else:
                warn("That is not a valid SHA-256 (64 hex characters). Skipped.")

    def scan(self) -> None:
        info("Scanning for drives…")
        try:
            self.drives = scan_drives(self.include_internal)
        except CliError as e:
            err(str(e))
            return
        print_drives(self.drives)
        if self.drive and all(d.fingerprint() != self.drive.fingerprint() for d in self.drives):
            warn("The previously selected drive is no longer present.")
            self.drive = None

    def select_drive(self) -> None:
        if not self.drives:
            self.scan()
        if not self.drives:
            return
        print_drives(self.drives)
        choice = ask("Drive number (Enter to cancel)")
        if choice.isdigit() and 1 <= int(choice) <= len(self.drives):
            self.drive = self.drives[int(choice) - 1]
            ok(f"Selected {self.drive.ident}: {self.drive.title}, {human_size(self.drive.size)}")
        elif choice:
            warn("Not a valid number.")

    def edit_options(self) -> None:
        o = self.opts
        while True:
            print()
            print(f"  {bold('1')}  Image mode        : {o.mode}   {dim('(auto / windows / linux)')}")
            print(f"  {bold('2')}  Filesystem        : {o.fs}   {dim('(Windows installers: FAT32 / ExFAT)')}")
            print(f"  {bold('3')}  Verify after write: {'on' if o.verify else 'off'}   {dim('(raw writes only)')}")
            print(f"  {bold('4')}  Eject when done   : {'on' if o.eject else 'off'}")
            print(f"  {bold('5')}  Volume label      : {o.label}   {dim('(Windows installers)')}")
            print(f"  {bold('6')}  Expected SHA-256  : {o.checksum[:16] + '…' if o.checksum else 'none'}")
            print(f"  {bold('7')}  Dry run           : {'on' if o.dry_run else 'off'}   {dim('(show what would happen)')}")
            print(f"  {bold('b')}  Back")
            choice = ask("Option").lower()
            if choice == "1":
                o.mode = {"auto": "windows", "windows": "linux", "linux": "auto"}[o.mode]
            elif choice == "2":
                o.fs = "ExFAT" if o.fs == "FAT32" else "FAT32"
            elif choice == "3":
                o.verify = not o.verify
            elif choice == "4":
                o.eject = not o.eject
            elif choice == "5":
                o.label = (ask("Label (max 11 letters/digits)", o.label).upper()[:11]) or o.label
            elif choice == "6":
                value = ask("SHA-256 (Enter to clear)")
                if not value:
                    o.checksum = ""
                elif is_valid_sha256(value):
                    o.checksum = value.lower()
                else:
                    warn("That is not a valid SHA-256.")
            elif choice == "7":
                o.dry_run = not o.dry_run
            elif choice in ("b", ""):
                return

    def open_folder(self) -> None:
        if self.image:
            reveal_in_file_manager(self.image)
        else:
            reveal_in_file_manager(os.path.expanduser("~/Downloads"))

    def start(self) -> None:
        if not self.image:
            warn("Choose an ISO / image first (option 1).")
            return
        if not self.drive:
            warn("Select a drive first (options 2 and 3).")
            return
        try:
            preflight(self.image, self.opts)
        except CliError as e:
            err(str(e))
            return
        if not self.opts.dry_run and not self.drive.is_file and os.geteuid() != 0:
            info("Writing needs administrator rights. Restarting with sudo (your selections are kept)…")
            relaunch_with_sudo(self)
            return
        # Rescan right before writing: the drive must still be the one the user picked.
        if not self.drive.is_file:
            fresh = [d for d in scan_drives(self.include_internal) if d.ident == self.drive.ident]
            if not fresh or fresh[0].fingerprint() != self.drive.fingerprint():
                err("The selected drive changed or disappeared. Scan again and select it again.")
                self.drive = None
                return
            self.drive = fresh[0]
        try:
            do_write(self.image, self.drive, self.opts)
            return True
        except UserAbort:
            warn("Cancelled. Nothing was changed.")
        except CliError as e:
            err(str(e))
        return False

    def run(self) -> None:
        actions = {"1": self.choose_image, "2": self.scan, "3": self.select_drive, "4": self.edit_options,
                   "5": self.open_folder, "6": self.start}
        while True:
            self.header()
            try:
                choice = self.menu()
            except UserAbort:
                print()
                return
            if choice in ("q", "quit", "exit"):
                return
            action = actions.get(choice)
            if not action:
                warn("Choose one of the numbers in the menu.")
                continue
            try:
                action()
            except UserAbort:
                warn("Cancelled.")
            except KeyboardInterrupt:
                print()
                warn("Interrupted.")
            except CliError as e:
                err(str(e))


# --------------------------------------------------------------------------- #
# sudo relaunch (keeps the user's selections)
# --------------------------------------------------------------------------- #
def relaunch_with_sudo(session: Session) -> None:
    state = {
        "image": session.image,
        "drive": session.drive.ident if session.drive else None,
        "include_internal": session.include_internal,
        "opts": session.opts.__dict__,
    }
    fd, path = tempfile.mkstemp(prefix="ubm-state-", suffix=".json")
    with os.fdopen(fd, "w") as f:
        json.dump(state, f)
    os.chmod(path, 0o644)
    cmd = ["sudo", sys.executable, os.path.abspath(__file__), "--resume", path]
    try:
        os.execvp("sudo", cmd)
    except OSError as e:
        os.unlink(path)
        raise CliError(f"Can't run sudo: {e.strerror}")


def resume_session(path: str) -> Session:
    with open(path) as f:
        state = json.load(f)
    try:
        os.unlink(path)
    except OSError:
        pass
    session = Session(include_internal=state.get("include_internal", False), opts=Options(**state["opts"]))
    session.image = state.get("image")
    if state.get("drive"):
        session.drives = scan_drives(session.include_internal)
        session.drive = next((d for d in session.drives if d.ident == state["drive"]), None)
        if not session.drive:
            warn("The selected drive is not available any more. Select it again.")
    return session


# --------------------------------------------------------------------------- #
# Command line
# --------------------------------------------------------------------------- #
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="usbbootmaker",
        description="USB Boot Maker CLI: bootable USB drives from Windows and Linux images. "
                    "Run without arguments for the interactive menu.")
    p.add_argument("--list", action="store_true", help="list removable drives and exit")
    p.add_argument("--check", action="store_true",
                   help="check required tools and offer to install missing ones (brew / apt / dnf / ...)")
    p.add_argument("--all", action="store_true", help="include internal drives in scans (dangerous)")
    p.add_argument("--image", help="ISO / .img / .gz file, or a folder with Windows installer files")
    p.add_argument("--device", help="target: device name (disk4, sdb), /dev path, or a plain file for testing")
    p.add_argument("--mode", choices=["auto", "windows", "linux"], default="auto", help="image type (default: auto)")
    p.add_argument("--fs", choices=["FAT32", "ExFAT"], default="FAT32", help="filesystem for Windows installers")
    p.add_argument("--label", default="USBBOOT", help="volume label for Windows installers")
    p.add_argument("--checksum", default="", help="expected SHA-256 of the image")
    p.add_argument("--no-verify", action="store_true", help="skip read-back verification")
    p.add_argument("--no-eject", action="store_true", help="don't eject the drive when done")
    p.add_argument("--yes", "-y", action="store_true", help="don't ask to type the device name (non-interactive)")
    p.add_argument("--dry-run", action="store_true", help="show what would happen, change nothing")
    p.add_argument("--resume", help=argparse.SUPPRESS)
    p.add_argument("--version", action="version", version=f"usbbootmaker {VERSION}")
    return p


def resolve_device(spec: str, include_internal: bool) -> Drive:
    if os.path.exists(spec) and not spec.startswith("/dev/") and os.path.isfile(spec):
        return drive_from_file(spec)
    drives = scan_drives(include_internal)
    name = spec[len("/dev/"):] if spec.startswith("/dev/") else spec
    name = name[1:] if IS_MAC and name.startswith("rdisk") else name
    for d in drives:
        if d.ident == name or d.ident == name.replace("rdisk", "disk"):
            return d
    if not os.path.exists(spec) and not spec.startswith("/dev/") and "/" in spec:
        return drive_from_file(spec)  # a new file to create (testing)
    raise CliError(f"Drive '{spec}' was not found among removable drives. Use --list to see them.")


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.check:
            return check_deps(args.yes)
        if args.list:
            print_drives(scan_drives(args.all))
            return 0
        if args.resume:
            session = resume_session(args.resume)
            if session.image and session.drive:
                return 0 if session.start() else 1
            session.run()
            return 0
        opts = Options(mode=args.mode, fs=args.fs, verify=not args.no_verify, eject=not args.no_eject,
                       label=args.label, checksum=args.checksum, dry_run=args.dry_run)
        ensure_all_tools(args.yes, args.dry_run)      # offer to install every missing tool, once, up front
        if args.image or args.device:
            if not (args.image and args.device):
                raise CliError("Use --image and --device together (or neither for the interactive menu).")
            drive = resolve_device(args.device, args.all)
            preflight(os.path.abspath(os.path.expanduser(args.image)), opts, args.yes)
            if not drive.is_file and not args.dry_run and os.geteuid() != 0:
                os.execvp("sudo", ["sudo", sys.executable, os.path.abspath(__file__)] + (argv if argv is not None else sys.argv[1:]))
            do_write(os.path.abspath(os.path.expanduser(args.image)), drive, opts, assume_yes=args.yes)
            return 0
        if not sys.stdin.isatty() and not os.environ.get("UBM_ALLOW_PIPE"):
            warn("Not running in a terminal; interactive menu may not work. Set UBM_ALLOW_PIPE=1 to force it.")
        Session(include_internal=args.all, opts=opts).run()
        return 0
    except UserAbort:
        warn("Cancelled. Nothing was changed.")
        return 130
    except KeyboardInterrupt:
        print()
        warn("Interrupted.")
        return 130
    except CliError as e:
        err(str(e))
        return 1


if __name__ == "__main__":
    sys.exit(main())
