#!/usr/bin/env python3
"""
Viper - interaktiver Datentraeger-Loescher und Formatierer fuer Linux.

Sicherheitsmodell:
- Standardmaessig nur Trockenlauf. Reale Schreiboperationen erfordern --execute.
- System-/Root-Datentraeger werden gesperrt.
- Nur ganze Blockgeraete vom Typ "disk" sind zulaessig.
- Vor dem Start muss der exakte Geraetepfad bestaetigt werden.

Copyright: xenion405
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import re
import secrets
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Sequence

VERSION = "0.1.0"
LOG_PATH = Path("/var/log/viper.log")


class C:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"


USE_COLOR = sys.stdout.isatty()
DRY_RUN = True


def color(text: str, code: str) -> str:
    return f"{code}{text}{C.RESET}" if USE_COLOR else text


def banner() -> None:
    art = r"""
██╗   ██╗██╗██████╗ ███████╗██████╗
██║   ██║██║██╔══██╗██╔════╝██╔══██╗
██║   ██║██║██████╔╝█████╗  ██████╔╝
╚██╗ ██╔╝██║██╔═══╝ ██╔══╝  ██╔══██╗
 ╚████╔╝ ██║██║     ███████╗██║  ██║
  ╚═══╝  ╚═╝╚═╝     ╚══════╝╚═╝  ╚═╝              
"""
    print(color(art, C.GREEN))
    print(color("              by xenion405", C.MAGENTA))
    print(color(f"              Viper v{VERSION}", C.DIM))
    print()


class ViperError(RuntimeError):
    pass


@dataclass(frozen=True)
class Device:
    path: str
    name: str
    size: int
    model: str
    vendor: str
    tran: str
    rota: bool
    removable: bool
    readonly: bool
    mounted: bool
    root_disk: bool
    detected_kind: str

    @property
    def protected(self) -> bool:
        return self.root_disk or self.readonly


KIND_LABELS = {
    "hdd": "HDD",
    "ssd": "SATA/SAS-SSD",
    "nvme": "NVMe-SSD",
    "usb": "USB-Stick/-Datentraeger",
    "sd": "SD-/microSD-Karte",
}

FS_COMMANDS: dict[str, tuple[str, list[str]]] = {
    "ext4": ("mkfs.ext4", ["mkfs.ext4", "-F"]),
    "exfat": ("mkfs.exfat", ["mkfs.exfat"]),
    "fat32": ("mkfs.vfat", ["mkfs.vfat", "-F", "32"]),
    "ntfs": ("mkfs.ntfs", ["mkfs.ntfs", "-F", "-f"]),
    "xfs": ("mkfs.xfs", ["mkfs.xfs", "-f"]),
    "btrfs": ("mkfs.btrfs", ["mkfs.btrfs", "-f"]),
}


def setup_logging() -> None:
    try:
        logging.basicConfig(
            filename=LOG_PATH,
            level=logging.INFO,
            format="%(asctime)s %(levelname)s %(message)s",
        )
    except OSError:
        logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")


def command_exists(name: str) -> bool:
    return shutil.which(name) is not None


def shell_join(args: Sequence[str]) -> str:
    import shlex

    return " ".join(shlex.quote(str(arg)) for arg in args)


def run(
    args: Sequence[str],
    *,
    capture: bool = False,
    check: bool = True,
    destructive: bool = False,
) -> subprocess.CompletedProcess[str]:
    cmd = [str(arg) for arg in args]
    logging.info("command%s: %s", " [destructive]" if destructive else "", shell_join(cmd))

    if destructive and DRY_RUN:
        print(color("[TROCKENLAUF] ", C.YELLOW) + shell_join(cmd))
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    if destructive:
        print(color("[AUSFUEHRUNG] ", C.RED) + shell_join(cmd))

    try:
        return subprocess.run(
            cmd,
            text=True,
            capture_output=capture,
            check=check,
        )
    except FileNotFoundError as exc:
        raise ViperError(f"Befehl fehlt: {cmd[0]}") from exc
    except subprocess.CalledProcessError as exc:
        detail = (exc.stderr or exc.stdout or "").strip()
        suffix = f"\n{detail}" if detail else ""
        raise ViperError(f"Befehl fehlgeschlagen: {shell_join(cmd)}{suffix}") from exc


def read_json_command(args: Sequence[str]) -> dict[str, Any]:
    result = run(args, capture=True)
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise ViperError(f"Ungueltige JSON-Ausgabe von {args[0]}") from exc


def human_size(size: int) -> str:
    units = ["B", "KiB", "MiB", "GiB", "TiB", "PiB"]
    value = float(size)
    for unit in units:
        if value < 1024 or unit == units[-1]:
            return f"{value:.1f} {unit}" if unit != "B" else f"{int(value)} B"
        value /= 1024
    return f"{size} B"


def flatten(nodes: Iterable[dict[str, Any]]) -> Iterable[dict[str, Any]]:
    for node in nodes:
        yield node
        children = node.get("children") or []
        yield from flatten(children)


def node_has_mount(node: dict[str, Any]) -> bool:
    mountpoints = node.get("mountpoints") or []
    if isinstance(mountpoints, str):
        mountpoints = [mountpoints]
    if any(mp for mp in mountpoints):
        return True
    return any(node_has_mount(child) for child in (node.get("children") or []))


def top_level_disk(path: str) -> str | None:
    """Loest Partition/Mapper rekursiv auf den zugrunde liegenden Datentraeger auf."""
    current = path.strip()
    if not current or not current.startswith("/dev/"):
        return None

    seen: set[str] = set()
    while current not in seen:
        seen.add(current)
        result = run(["lsblk", "-ndo", "PKNAME", current], capture=True, check=False)
        parent = result.stdout.strip().splitlines()[0] if result.stdout.strip() else ""
        if not parent:
            device_type = run(["lsblk", "-ndo", "TYPE", current], capture=True, check=False).stdout.strip()
            return current if device_type == "disk" else None
        current = parent if parent.startswith("/dev/") else f"/dev/{parent}"
    return None


def detect_critical_disks() -> set[str]:
    """Datentraeger, die das laufende System oder aktiven Swap tragen."""
    critical: set[str] = set()
    for mountpoint in ("/", "/boot", "/boot/efi"):
        result = run(["findmnt", "-n", "-o", "SOURCE", mountpoint], capture=True, check=False)
        source = result.stdout.strip()
        disk = top_level_disk(source) if source else None
        if disk:
            critical.add(os.path.realpath(disk))

    if command_exists("swapon"):
        result = run(["swapon", "--show=NAME", "--noheadings"], capture=True, check=False)
        for source in result.stdout.splitlines():
            disk = top_level_disk(source.strip())
            if disk:
                critical.add(os.path.realpath(disk))
    return critical


def as_bool(value: Any) -> bool:
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "on"}
    return bool(value)


def subtree_mountpoints(node: dict[str, Any]) -> set[str]:
    result: set[str] = set()
    mountpoints = node.get("mountpoints") or []
    if isinstance(mountpoints, str):
        mountpoints = [mountpoints]
    result.update(str(mp) for mp in mountpoints if mp)
    for child in node.get("children") or []:
        result.update(subtree_mountpoints(child))
    return result


def detect_kind(node: dict[str, Any]) -> str:
    path = str(node.get("path") or "")
    tran = str(node.get("tran") or "").lower()
    rota = as_bool(node.get("rota"))

    if path.startswith("/dev/nvme"):
        return "nvme"
    if path.startswith("/dev/mmcblk"):
        return "sd"
    if tran == "usb":
        return "usb"
    if rota:
        return "hdd"
    return "ssd"


def list_devices() -> list[Device]:
    data = read_json_command(
        [
            "lsblk",
            "--json",
            "--bytes",
            "--paths",
            "--output",
            "PATH,NAME,TYPE,SIZE,MODEL,VENDOR,TRAN,ROTA,RM,RO,MOUNTPOINTS",
        ]
    )
    critical_disks = detect_critical_disks()
    devices: list[Device] = []

    for node in data.get("blockdevices", []):
        if node.get("type") != "disk":
            continue
        path = str(node.get("path") or "")
        if not path or path.startswith(("/dev/loop", "/dev/zram", "/dev/sr")):
            continue
        devices.append(
            Device(
                path=path,
                name=str(node.get("name") or Path(path).name),
                size=int(node.get("size") or 0),
                model=str(node.get("model") or "").strip(),
                vendor=str(node.get("vendor") or "").strip(),
                tran=str(node.get("tran") or "").strip(),
                rota=as_bool(node.get("rota")),
                removable=as_bool(node.get("rm")),
                readonly=as_bool(node.get("ro")),
                mounted=node_has_mount(node),
                root_disk=(
                    os.path.realpath(path) in critical_disks
                    or bool(
                        subtree_mountpoints(node)
                        & {"/", "/boot", "/boot/efi", "/run/live/medium", "/lib/live/mount/medium"}
                    )
                ),
                detected_kind=detect_kind(node),
            )
        )
    return devices


def print_devices(devices: Sequence[Device]) -> None:
    print(color("Verfuegbare Datentraeger", C.BOLD))
    print("=" * 88)
    for index, dev in enumerate(devices, 1):
        flags: list[str] = []
        if dev.root_disk:
            flags.append(color("SYSTEM", C.RED))
        if dev.readonly:
            flags.append(color("READ-ONLY", C.RED))
        if dev.mounted:
            flags.append(color("EINGEHAENGT", C.YELLOW))
        if dev.removable:
            flags.append("ENTFERNBAR")
        flag_text = ", ".join(flags) if flags else "OK"
        model = " ".join(part for part in (dev.vendor, dev.model) if part) or "Unbekanntes Modell"
        print(
            f"[{index:>2}] {dev.path:<18} {human_size(dev.size):>10}  "
            f"{KIND_LABELS[dev.detected_kind]:<21} {model[:25]:<25} [{flag_text}]"
        )
    print("=" * 88)


def select_device(devices: Sequence[Device], preselected: str | None) -> Device:
    if preselected:
        real = os.path.realpath(preselected)
        for dev in devices:
            if os.path.realpath(dev.path) == real:
                selected = dev
                break
        else:
            raise ViperError(f"Kein zulaessiger ganzer Datentraeger: {preselected}")
    else:
        print_devices(devices)
        raw = input("Datentraeger waehlen (Nummer, q=Abbruch): ").strip().lower()
        if raw in {"q", "quit", "exit"}:
            raise KeyboardInterrupt
        try:
            selected = devices[int(raw) - 1]
        except (ValueError, IndexError) as exc:
            raise ViperError("Ungueltige Auswahl") from exc

    if selected.root_disk:
        raise ViperError(f"Viper blockiert den Systemdatentraeger {selected.path}.")
    if selected.readonly:
        raise ViperError(f"{selected.path} ist schreibgeschuetzt.")
    return selected


def select_kind(detected: str) -> str:
    print(f"\nErkannt: {color(KIND_LABELS[detected], C.CYAN)}")
    print("[Enter] Erkennung uebernehmen")
    print("[1] HDD")
    print("[2] SATA/SAS-SSD")
    print("[3] NVMe-SSD")
    print("[4] USB-Stick/-Datentraeger")
    print("[5] SD-/microSD-Karte")
    mapping = {"1": "hdd", "2": "ssd", "3": "nvme", "4": "usb", "5": "sd"}
    raw = input("Medientyp: ").strip()
    return mapping.get(raw, detected)


def recommended_wipe(kind: str) -> str:
    return "zero" if kind in {"hdd", "usb", "sd"} else "discard"


def select_wipe(kind: str) -> str:
    recommended = recommended_wipe(kind)
    rec_text = "vollstaendig mit Nullen" if recommended == "zero" else "Discard/TRIM"
    print(f"\nEmpfehlung fuer {KIND_LABELS[kind]}: {color(rec_text, C.GREEN)}")
    print("[1] Empfohlene Methode")
    print("[2] Vollstaendig mit Nullen ueberschreiben")
    print("[3] Discard/TRIM (nur wenn vom Geraet unterstuetzt)")
    print("[4] Nur neu partitionieren und formatieren")
    raw = input("Loeschmethode [1]: ").strip() or "1"
    mapping = {"1": recommended, "2": "zero", "3": "discard", "4": "format-only"}
    if raw not in mapping:
        raise ViperError("Ungueltige Loeschmethode")
    if mapping[raw] == "zero" and kind in {"ssd", "nvme"}:
        print(color("Warnung: Null-Ueberschreiben verursacht bei Flash-Speicher unnoetigen Verschleiss.", C.YELLOW))
    if kind in {"usb", "sd"}:
        print(color("Hinweis: Wegen Wear-Leveling ist forensisch sicheres Loeschen bei Flash-Medien nicht garantiert.", C.YELLOW))
    return mapping[raw]


def select_table() -> str:
    print("\nPartitionstabelle:")
    print("[1] GPT (empfohlen)")
    print("[2] MBR/msdos (alte Geraete)")
    raw = input("Auswahl [1]: ").strip() or "1"
    if raw not in {"1", "2"}:
        raise ViperError("Ungueltige Partitionstabelle")
    return "gpt" if raw == "1" else "msdos"


def select_filesystem() -> str:
    choices = [
        ("ext4", "Linux"),
        ("exfat", "Linux/Windows/macOS, grosse Dateien"),
        ("fat32", "Maximale Kompatibilitaet, Dateien max. 4 GiB"),
        ("ntfs", "Windows/Linux"),
        ("xfs", "Linux"),
        ("btrfs", "Linux"),
    ]
    print("\nDateisystem:")
    for index, (name, description) in enumerate(choices, 1):
        print(f"[{index}] {name:<6} - {description}")
    raw = input("Auswahl [1]: ").strip() or "1"
    try:
        return choices[int(raw) - 1][0]
    except (ValueError, IndexError) as exc:
        raise ViperError("Ungueltiges Dateisystem") from exc


def sanitize_label(raw: str, fs: str) -> str:
    label = raw.strip() or "VIPER"
    if fs == "fat32":
        label = re.sub(r"[^A-Za-z0-9 _-]", "", label).upper()[:11]
    elif fs == "exfat":
        label = re.sub(r"[\\/:*?\"<>|]", "", label)[:15]
    elif fs == "ntfs":
        label = re.sub(r"[\\/:*?\"<>|]", "", label)[:32]
    else:
        label = re.sub(r"[^A-Za-z0-9_.-]", "_", label)[:16]
    return label or "VIPER"


def partition_path(device: str, number: int = 1) -> str:
    return f"{device}p{number}" if device[-1].isdigit() else f"{device}{number}"


def descendant_nodes(device: str) -> list[dict[str, Any]]:
    data = read_json_command(
        ["lsblk", "--json", "--paths", "--output", "PATH,TYPE,MOUNTPOINTS", device]
    )
    return list(flatten(data.get("blockdevices", [])))


def unmount_and_swapoff(device: str) -> None:
    nodes = descendant_nodes(device)
    node_paths = {str(node.get("path")) for node in nodes if node.get("path")}

    if command_exists("swapon"):
        swaps = run(["swapon", "--show=NAME", "--noheadings"], capture=True, check=False).stdout.splitlines()
        for swap in swaps:
            swap = swap.strip()
            if swap in node_paths:
                run(["swapoff", swap], destructive=True)

    mounted_paths: list[str] = []
    for node in nodes:
        mps = node.get("mountpoints") or []
        if isinstance(mps, str):
            mps = [mps]
        mounted_paths.extend(str(mp) for mp in mps if mp)

    for mountpoint in sorted(set(mounted_paths), key=len, reverse=True):
        run(["umount", mountpoint], destructive=True)


def check_discard_support(device: str) -> bool:
    result = run(["lsblk", "-ndo", "DISC-MAX", device], capture=True, check=False)
    value = result.stdout.strip()
    if not value:
        return False
    # --bytes is not universally combined with DISC-MAX output, so accept any non-zero form.
    return value not in {"0", "0B", "0 B", "0.0B", "0.0 B"}


def wipe_device(device: str, method: str) -> None:
    if method == "format-only":
        print(color("Loeschschritt uebersprungen.", C.YELLOW))
        return
    if method == "zero":
        run(
            ["dd", "if=/dev/zero", f"of={device}", "bs=16M", "status=progress", "conv=fsync"],
            destructive=True,
        )
        run(["sync"], destructive=True)
        return
    if method == "discard":
        if not command_exists("blkdiscard"):
            raise ViperError("blkdiscard fehlt (Paket util-linux).")
        if not DRY_RUN and not check_discard_support(device):
            raise ViperError(
                "Der Datentraeger meldet keine Discard-Unterstuetzung. "
                "Waehle stattdessen Null-Ueberschreiben oder Nur formatieren."
            )
        run(["blkdiscard", "--force", device], destructive=True)
        return
    raise ViperError(f"Unbekannte Loeschmethode: {method}")


def wait_for_partition(path: str, timeout: float = 12.0) -> None:
    if DRY_RUN:
        return
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if os.path.exists(path):
            return
        time.sleep(0.25)
    raise ViperError(f"Neue Partition ist nicht erschienen: {path}")


def partition_device(device: str, table: str) -> str:
    run(["wipefs", "--all", "--force", device], destructive=True)
    run(["parted", "--script", "--align", "optimal", device, "mklabel", table], destructive=True)
    run(
        ["parted", "--script", "--align", "optimal", device, "mkpart", "primary", "1MiB", "100%"],
        destructive=True,
    )
    if command_exists("partprobe"):
        run(["partprobe", device], destructive=True)
    if command_exists("udevadm"):
        run(["udevadm", "settle"], destructive=True)
    part = partition_path(device)
    wait_for_partition(part)
    return part


def format_partition(partition: str, fs: str, label: str) -> None:
    executable, base = FS_COMMANDS[fs]
    if not command_exists(executable):
        raise ViperError(f"Formatierungsprogramm fehlt: {executable}")

    command = list(base)
    if fs == "ext4":
        command += ["-L", label, partition]
    elif fs == "exfat":
        command += ["-L", label, partition]
    elif fs == "fat32":
        command += ["-n", label, partition]
    elif fs == "ntfs":
        command += ["-L", label, partition]
    elif fs == "xfs":
        command += ["-L", label, partition]
    elif fs == "btrfs":
        command += ["-L", label, partition]
    else:
        raise ViperError(f"Unbekanntes Dateisystem: {fs}")
    run(command, destructive=True)


def verify_dependencies(fs: str | None = None, wipe: str | None = None, *, listing_only: bool = False) -> None:
    required = ["lsblk", "findmnt"]
    if not listing_only:
        required += ["umount", "wipefs", "parted", "dd", "sync"]
        if wipe == "discard":
            required.append("blkdiscard")
    if fs:
        required.append(FS_COMMANDS[fs][0])
    missing = sorted(name for name in required if not command_exists(name))
    if missing:
        raise ViperError("Fehlende Programme: " + ", ".join(missing))


def require_root_for_execute() -> None:
    if not DRY_RUN and os.geteuid() != 0:
        raise ViperError("Reale Ausfuehrung erfordert Root: sudo viper --execute")


def confirm_plan(device: Device, kind: str, wipe: str, table: str, fs: str, label: str) -> None:
    wipe_label = {
        "zero": "vollstaendig mit Nullen ueberschreiben",
        "discard": "Discard/TRIM",
        "format-only": "nur neu partitionieren/formatieren",
    }[wipe]
    print("\n" + color("AUSGEWAEHLTER PLAN", C.BOLD))
    print(f"  Datentraeger:     {device.path} ({human_size(device.size)})")
    print(f"  Modell:           {' '.join(x for x in (device.vendor, device.model) if x) or 'unbekannt'}")
    print(f"  Medientyp:        {KIND_LABELS[kind]}")
    print(f"  Loeschmethode:    {wipe_label}")
    print(f"  Partitionstabelle:{table}")
    print(f"  Dateisystem:      {fs}")
    print(f"  Label:            {label}")
    print(f"  Modus:            {'TROCKENLAUF' if DRY_RUN else 'ECHTE AUSFUEHRUNG'}")

    if DRY_RUN:
        print(color("\nEs werden keine Daten veraendert. Nutze --execute fuer den echten Lauf.", C.YELLOW))
        return

    print(color("\nWARNUNG: ALLE DATEN AUF DIESEM DATENTRAEGER WERDEN UNWIEDERBRINGLICH GELOESCHT.", C.RED))
    phrase = f"VIPER {device.path}"
    typed = input(f"Tippe exakt '{phrase}': ").strip()
    if typed != phrase:
        raise ViperError("Bestaetigung stimmt nicht. Abbruch.")
    code = f"{secrets.randbelow(1_000_000):06d}"
    print(f"Sicherheitscode: {color(code, C.YELLOW)}")
    if input("Code wiederholen: ").strip() != code:
        raise ViperError("Sicherheitscode falsch. Abbruch.")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="viper",
        description="Sicherheitsorientierter Datentraeger-Loescher und Formatierer fuer Linux.",
    )
    parser.add_argument("--execute", action="store_true", help="destruktive Befehle wirklich ausfuehren")
    parser.add_argument("--device", help="Datentraeger vorwaehlen, z. B. /dev/sdb")
    parser.add_argument("--list", action="store_true", help="Datentraeger anzeigen und beenden")
    parser.add_argument("--no-color", action="store_true", help="ANSI-Farben deaktivieren")
    parser.add_argument("--version", action="version", version=f"Viper {VERSION}")
    return parser.parse_args()


def main() -> int:
    global USE_COLOR, DRY_RUN
    args = parse_args()
    USE_COLOR = USE_COLOR and not args.no_color
    DRY_RUN = not args.execute
    setup_logging()
    banner()

    try:
        verify_dependencies(listing_only=True)
        require_root_for_execute()
        devices = list_devices()
        if not devices:
            raise ViperError("Keine geeigneten Datentraeger gefunden.")
        if args.list:
            print_devices(devices)
            return 0

        device = select_device(devices, args.device)
        kind = select_kind(device.detected_kind)
        wipe = select_wipe(kind)
        table = select_table()
        fs = select_filesystem()
        label = sanitize_label(input("Datentraeger-Label [VIPER]: "), fs)
        verify_dependencies(fs, wipe)
        confirm_plan(device, kind, wipe, table, fs, label)

        unmount_and_swapoff(device.path)
        wipe_device(device.path, wipe)
        partition = partition_device(device.path, table)
        format_partition(partition, fs, label)

        print(color("\nViper hat den Vorgang erfolgreich abgeschlossen.", C.GREEN))
        print(f"Neue Partition: {partition}")
        if DRY_RUN:
            print(color("Dies war nur ein Trockenlauf; es wurde nichts veraendert.", C.YELLOW))
        return 0
    except KeyboardInterrupt:
        print("\nAbgebrochen.")
        return 130
    except ViperError as exc:
        logging.error("%s", exc)
        print(color(f"\nFEHLER: {exc}", C.RED), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
