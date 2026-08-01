# Viper

```text
 __      ___
██╗   ██╗██╗██████╗ ███████╗██████╗
██║   ██║██║██╔══██╗██╔════╝██╔══██╗
██║   ██║██║██████╔╝█████╗  ██████╔╝
╚██╗ ██╔╝██║██╔═══╝ ██╔══╝  ██╔══██╗
 ╚████╔╝ ██║██║     ███████╗██║  ██║
  ╚═══╝  ╚═╝╚═╝     ╚══════╝╚═╝  ╚═╝
              by xenion405
```

Viper ist ein interaktiver, sicherheitsorientierter Datentraeger-Loescher und
Formatierer fuer Linux/Kali Linux.

## Sicherheitskonzept

- Standardmaessig laeuft Viper als **Trockenlauf** und zeigt nur Befehle an.
- Reale Aenderungen erfordern explizit `--execute` und Root-Rechte.
- Der erkannte System-/Root-Datentraeger wird blockiert.
- Viper akzeptiert nur ganze Blockgeraete vom Typ `disk`, keine Partitionen.
- Vor dem echten Start sind der exakte Geraetepfad und ein Zufallscode einzugeben.
- Eingehangene Dateisysteme und Swap-Bereiche des Zieldatentraegers werden ausgehaengt.

Trotzdem gilt: **Vor jeder Ausfuehrung Geraetepfad, Groesse und Modell selbst pruefen.**

## Loeschmethoden

| Medium | Viper-Empfehlung | Hinweis |
|---|---|---|
| HDD | Vollstaendig mit Nullen ueberschreiben | Ein kompletter Durchgang reicht fuer normale Wiederverwendung aus. |
| SATA/SAS-SSD | `blkdiscard` | Schnell und verschleissarm, aber nicht mit einem zertifizierten Firmware-Sanitize gleichzusetzen. |
| NVMe-SSD | `blkdiscard` | Firmware-Sanitize ist absichtlich noch nicht automatisiert. |
| USB-Stick | Nullen ueberschreiben | Wegen internem Wear-Leveling nicht garantiert forensisch sicher. |
| SD-/microSD | Nullen ueberschreiben | Wegen internem Wear-Leveling nicht garantiert forensisch sicher. |

Viper verspricht keine zertifizierte Datenvernichtung. Fuer Verkauf, Compliance oder
hochvertrauliche Daten sollte ein vom Hersteller dokumentierter ATA-/NVMe-Sanitize-
Vorgang oder physische Vernichtung nach der jeweils geltenden Richtlinie verwendet werden.

## Installation unter Linux

```bash
sudo apt update
sudo apt install python3 util-linux parted e2fsprogs exfatprogs dosfstools ntfs-3g xfsprogs btrfs-progs
chmod +x viper.py install.sh uninstall.sh
sudo ./install.sh
```

## Verwendung

Datentraeger anzeigen:

```bash
viper --list
```

Sicherer Trockenlauf:

```bash
viper
```

Trockenlauf mit vorgewaehltem Datentraeger:

```bash
viper --device /dev/sdb
```

Echte Ausfuehrung:

```bash
sudo viper --execute
```

## Unterstuetzte Dateisysteme

- ext4
- exFAT
- FAT32
- NTFS
- XFS
- Btrfs

## Log

Bei Root-Ausfuehrung schreibt Viper Befehle und Fehler nach:

```text
/var/log/viper.log
```

## Aktueller Umfang

Version 0.1.0 ist eine Terminal-Anwendung. ATA Secure Erase und NVMe Sanitize
werden absichtlich nicht automatisch ausgefuehrt, weil fehlerhafte oder nicht
vollstaendig unterstuetzte Firmware-Aufrufe Laufwerke sperren oder unbrauchbar
machen koennen.
