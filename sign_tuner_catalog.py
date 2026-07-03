"""sign_tuner_catalog — Dev/Build-Helfer fuer den system_tuner-Katalog-Signaturschluessel.

B2 (Prod-Signing-Key-Rotation). Drei Subcommands:

    keygen Erzeugt ein NEUES Ed25519-Schluesselpaar. Gibt den PUBLIC-Key
             (base64, 32B) auf stdout aus (-> einsetzen in
             tools/system_tuner/data/catalog_signature.py:_PUBLIC_KEY_B64) und
             schreibt den PRIVATE-Key (base64) in die angegebene Datei.
             Der PRIVATE-Key wird NIE committet und gehoert NICHT ins Repo
             (siehe Empfehlung im Threat-Model / Session-Notiz B2).

    sign Signiert resources/system_tuner/catalog_v1.yaml mit dem privaten
             Key und schreibt resources/system_tuner/catalog_v1.yaml.sig.

    verify Prueft den aktuellen Katalog gegen den im Code eingebetteten
             Public-Key (Sanity-Check nach einem Tausch). Exit 0 = gueltig.

Beispiel-Rotation (Prod):
    # 1) auf der vertrauenswuerdigen Maschine:
    python sign_tuner_catalog.py keygen --out E:/secure/system_tuner_prod_signing_key.b64
    # -> Public-Key in catalog_signature.py:_PUBLIC_KEY_B64 eintragen
    # 2) Katalog neu signieren:
    python sign_tuner_catalog.py sign --private-key E:/secure/system_tuner_prod_signing_key.b64
    # 3) Sanity:
    python sign_tuner_catalog.py verify
    # 4) committen: catalog_signature.py + catalog_v1.yaml.sig (NIE den Private-Key)

ASCII-only Output (Windows-Konsole, cp1252-sicher).
"""

from __future__ import annotations

import argparse
import base64
import os
import sys
from pathlib import Path

# Repo-Root = Verzeichnis dieser Datei.
_ROOT = Path(__file__).resolve().parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import (  # noqa: E402
    Ed25519PrivateKey,
)

from tools.system_tuner.application.catalog_loader import (  # noqa: E402
    default_catalog_path,
    default_signature_path,
)
from tools.system_tuner.data.catalog_signature import (  # noqa: E402
    sign_catalog,
    verify_catalog,
)


def _raw_public_b64(private_key: Ed25519PrivateKey) -> str:
    raw = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return base64.b64encode(raw).decode()


def _raw_private_b64(private_key: Ed25519PrivateKey) -> str:
    raw = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return base64.b64encode(raw).decode()


def _write_private_key_restrictive(out_path: Path, priv_b64: str) -> bool:
    """Schreibt den Privatkey von Anfang an mit restriktiven Rechten (B4-P2).

    POSIX: ``os.open(O_CREAT|O_EXCL|O_WRONLY, 0o600)`` legt die Datei atomar mit
    0600 an (kein write_text-dann-chmod-Fenster); ``O_EXCL`` deckt zugleich die
    Overwrite-Pruefung. Windows: NTFS bildet POSIX-Mode-Bits NICHT auf ACLs ab —
    die Datei ist NICHT per Dateisystem-ACL geschuetzt; der Caller warnt explizit.

    Returns:
        ``True`` wenn der OS-Mode wirksam beschraenkt (POSIX); ``False`` auf
        Windows (kein wirksamer FS-Schutz -> Caller-Warnung).

    Raises:
        FileExistsError: wenn ``out_path`` bereits existiert (O_EXCL).
        OSError: bei sonstigen Schreibfehlern.
    """
    fd = os.open(out_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    try:
        os.write(fd, priv_b64.encode("utf-8"))
    finally:
        os.close(fd)
    return os.name != "nt"


def cmd_keygen(out_path: Path) -> int:
    # B4-P3: Privatkey NIE im Repo-Baum erzeugen (versehentlicher Commit-Pfad).
    try:
        resolved = out_path.resolve()
        if resolved == _ROOT or _ROOT in resolved.parents:
            print(f"[ABBRUCH] Out-Pfad liegt im Repo-Baum: {resolved}")
            print("          Privatkey AUSSERHALB des Repos erzeugen (verschluesselt/offline).")
            return 2
    except OSError:
        pass
    private_key = Ed25519PrivateKey.generate()
    pub_b64 = _raw_public_b64(private_key)
    priv_b64 = _raw_private_b64(private_key)
    try:
        restricted = _write_private_key_restrictive(out_path, priv_b64)
    except FileExistsError:
        print(f"[ABBRUCH] Zieldatei existiert bereits: {out_path}")
        print("          Vorhandenen Key NICHT versehentlich ueberschreiben.")
        return 2
    except OSError as exc:
        print(f"[ABBRUCH] Privatkey nicht schreibbar: {exc}")
        return 2
    print("== Ed25519-Schluesselpaar erzeugt ==")
    print(f"PRIVATE-Key geschrieben nach: {out_path}")
    if not restricted:
        print("  [WARNUNG] Windows: die Datei ist NICHT per Dateisystem-ACL geschuetzt")
        print("            (POSIX-Mode-Bits greifen auf NTFS nicht). JETZT manuell auf")
        print("            den Owner einschraenken ODER sofort in einen verschluesselten")
        print("            Offline-Store verschieben (s. B2-Empfehlung).")
    print("  -> NIE committen. Verschluesselt/offline aufbewahren (s. B2-Empfehlung).")
    print("")
    print("PUBLIC-Key (in catalog_signature.py:_PUBLIC_KEY_B64 eintragen):")
    print(f"  {pub_b64}")
    return 0


def cmd_sign(private_key_path: Path) -> int:
    if not private_key_path.is_file():
        print(f"[ABBRUCH] Private-Key nicht gefunden: {private_key_path}")
        return 2
    priv_b64 = private_key_path.read_text(encoding="utf-8").strip()
    catalog = default_catalog_path()
    sig_path = default_signature_path()
    if not catalog.is_file():
        print(f"[ABBRUCH] Katalog nicht gefunden: {catalog}")
        return 2
    signature = sign_catalog(catalog, priv_b64)
    sig_path.write_text(signature + "\n", encoding="utf-8")
    print(f"[OK] Katalog signiert: {catalog}")
    print(f"     Signatur geschrieben: {sig_path}")
    print("     Sanity-Check: 'python sign_tuner_catalog.py verify'")
    return 0


def cmd_verify() -> int:
    catalog = default_catalog_path()
    sig_path = default_signature_path()
    ok = verify_catalog(catalog, sig_path)
    if ok:
        print("[OK] Katalog-Signatur gueltig gegen den eingebetteten Public-Key.")
        return 0
    print("[FEHLER] Katalog-Signatur UNGUELTIG/fehlt.")
    print("         (Public-Key in catalog_signature.py passt nicht zur .sig,")
    print("          oder die .sig wurde nicht neu erzeugt.)")
    return 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="system_tuner Katalog-Signatur (keygen/sign/verify) -- B2-Rotation.",
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_keygen = sub.add_parser("keygen", help="Neues Ed25519-Schluesselpaar erzeugen.")
    p_keygen.add_argument(
        "--out",
        required=True,
        type=Path,
        help="Pfad fuer den PRIVATE-Key (base64). NICHT ins Repo.",
    )

    p_sign = sub.add_parser("sign", help="Katalog mit Private-Key signieren.")
    p_sign.add_argument(
        "--private-key",
        required=True,
        type=Path,
        help="Pfad zum PRIVATE-Key (base64).",
    )

    sub.add_parser("verify", help="Aktuellen Katalog gegen eingebetteten Public-Key pruefen.")

    args = parser.parse_args(argv)
    if args.cmd == "keygen":
        return cmd_keygen(args.out)
    if args.cmd == "sign":
        return cmd_sign(args.private_key)
    if args.cmd == "verify":
        return cmd_verify()
    return 2


if __name__ == "__main__":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except (AttributeError, ValueError):
        pass
    raise SystemExit(main())
