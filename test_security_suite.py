"""
test_security_suite.py
------------------------
Batería de pruebas de seguridad para PassVault. Simula escenarios de
ataque reales contra el propio vault (robo de archivo, manipulación,
fuerza bruta, etc.) y reporta PASS/FAIL por categoría, como un pentest
interno.

Uso:
    python test_security_suite.py

No requiere pytest ni dependencias extra más allá de las de requirements.txt.
"""

import os
import sys
import time
import shutil
import tempfile
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from vault_manager import VaultManager, WrongPasswordError, VaultError
from crypto_engine import CryptoEngine
from utils.lockout_manager import LockoutManager
from utils.audit_log import AuditLogger
from utils.audit import analyze_entries
from utils.password_gen import generate_password, estimate_strength
from utils import totp, anti_debug

RESULTS = []  # (categoria, nombre, paso: bool, detalle)


def check(categoria, nombre, condicion, detalle=""):
    RESULTS.append((categoria, nombre, bool(condicion), detalle))


def new_temp_path():
    fd, path = tempfile.mkstemp(suffix=".enc")
    os.close(fd)
    os.remove(path)
    return path


def cleanup(path):
    for suffix in ("", ".bak", ".lockout", ".audit.log", ".tmp"):
        p = path + suffix
        if os.path.exists(p):
            os.remove(p)


# ============================================================
# CONFIDENCIALIDAD
# ============================================================
def test_confidentiality():
    path = new_temp_path()
    vm = VaultManager(path)
    vm.create_vault("ConfiTest123456!")
    vm.add_entry("secreto-bancolombia.com", "usuario_secreto", "PasswordSecreta123!")

    with open(path, "rb") as f:
        raw = f.read()

    check("Confidencialidad", "El sitio no aparece en texto plano en el archivo",
          b"secreto-bancolombia.com" not in raw)
    check("Confidencialidad", "El usuario no aparece en texto plano en el archivo",
          b"usuario_secreto" not in raw)
    check("Confidencialidad", "La contraseña no aparece en texto plano en el archivo",
          b"PasswordSecreta123" not in raw)

    backup_path = path + "_backup_test"
    vm.export_backup(backup_path)
    with open(backup_path, "rb") as f:
        raw_backup = f.read()
    check("Confidencialidad", "El backup exportado tampoco expone texto plano",
          b"secreto-bancolombia.com" not in raw_backup)

    os.remove(backup_path)
    cleanup(path)


# ============================================================
# INTEGRIDAD
# ============================================================
def test_integrity():
    path = new_temp_path()
    vm = VaultManager(path)
    vm.create_vault("IntegridadTest123!")
    vm.add_entry("test.com", "user", "pass")
    vm.lock()

    # Ataque: voltear bits del ciphertext
    with open(path, "rb") as f:
        raw = bytearray(f.read())
    raw[-3] ^= 0xFF
    with open(path, "wb") as f:
        f.write(raw)

    vm2 = VaultManager(path)
    tampering_detected = False
    try:
        vm2.unlock("IntegridadTest123!")
    except WrongPasswordError:
        tampering_detected = True
    check("Integridad", "Manipulación del archivo cifrado es detectada (auth tag GCM)",
          tampering_detected)

    cleanup(path)


# ============================================================
# AUTENTICACIÓN
# ============================================================
def test_authentication():
    path = new_temp_path()
    vm = VaultManager(path)
    vm.create_vault("AuthTest123456!")
    vm.add_entry("site.com", "u", "p")
    vm.lock()

    vm2 = VaultManager(path)
    wrong_rejected = False
    try:
        vm2.unlock("PasswordIncorrecta999")
    except WrongPasswordError:
        wrong_rejected = True
    check("Autenticación", "Master password incorrecta es rechazada", wrong_rejected)

    vm3 = VaultManager(path)
    vm3.unlock("AuthTest123456!")
    check("Autenticación", "Master password correcta desbloquea y recupera los datos",
          len(vm3.get_entries()) == 1 and vm3.get_entries()[0]["site"] == "site.com")

    salt1 = CryptoEngine.generate_salt()
    salt2 = CryptoEngine.generate_salt()
    key_a = CryptoEngine.derive_key("MismaPassword123!", salt1)
    key_b = CryptoEngine.derive_key("MismaPassword123!", salt1)
    key_c = CryptoEngine.derive_key("MismaPassword123!", salt2)
    check("Autenticación", "Argon2id es determinístico (mismo password+salt = misma clave)",
          key_a == key_b)
    check("Autenticación", "Salts distintos generan claves distintas (aunque el password sea igual)",
          key_a != key_c)

    cleanup(path)


# ============================================================
# ANTI FUERZA BRUTA
# ============================================================
def test_brute_force_protection():
    path = new_temp_path()
    lm = LockoutManager(path)

    all_free = all(lm.register_failure() == 0 for _ in range(3))
    check("Anti fuerza bruta", "Primeros 3 intentos fallidos no generan espera", all_free)

    delay1 = lm.register_failure()
    check("Anti fuerza bruta", "4to intento activa lockout (>0s de espera)", delay1 > 0)

    delay2 = lm.register_failure()
    check("Anti fuerza bruta", "5to intento duplica el tiempo de espera (backoff exponencial)",
          delay2 == delay1 * 2)

    check("Anti fuerza bruta", "seconds_remaining() refleja el lockout activo",
          lm.seconds_remaining() > 0)

    lm.register_success()
    check("Anti fuerza bruta", "Un desbloqueo exitoso resetea el contador",
          lm.seconds_remaining() == 0 and lm.attempts_before_lockout() == 3)

    cleanup(path)


# ============================================================
# 2FA / TOTP
# ============================================================
def test_2fa():
    path = new_temp_path()
    vm = VaultManager(path)
    vm.create_vault("TOTPTest123456!")

    secret = totp.generate_secret()
    import pyotp
    valid_code = pyotp.TOTP(secret).now()

    check("2FA", "Código TOTP válido es aceptado", totp.verify_code(secret, valid_code))
    check("2FA", "Código TOTP inválido es rechazado", not totp.verify_code(secret, "000000"))
    check("2FA", "Código con formato inválido no rompe la verificación",
          not totp.verify_code(secret, "abc"))

    vm.enable_totp(secret)
    vm.lock()
    vm2 = VaultManager(path)
    vm2.unlock("TOTPTest123456!")
    check("2FA", "El secreto TOTP persiste cifrado dentro del vault tras re-abrir",
          vm2.totp_enabled and vm2.totp_secret == secret)

    cleanup(path)


# ============================================================
# BACKUPS Y RECUPERACIÓN
# ============================================================
def test_backups_and_recovery():
    path = new_temp_path()
    vm = VaultManager(path)
    vm.create_vault("BackupTest123456!")
    vm.add_entry("original.com", "u", "p")

    backup_path = path + "_export"
    vm.export_backup(backup_path)
    vm_restored = VaultManager(backup_path)
    vm_restored.unlock("BackupTest123456!")
    check("Backups", "El backup exportado se abre con la misma master password",
          len(vm_restored.get_entries()) == 1)
    os.remove(backup_path)

    # Simular error de usuario: borra todo, luego restaura la versión anterior
    vm.add_entry("segundo.com", "u2", "p2")
    entries_before_mistake = len(vm.get_entries())
    for e in list(vm.get_entries()):
        vm.delete_entry(e["id"])
    check("Backups", "Simulación: usuario borró todas las entradas por error",
          len(vm.get_entries()) == 0)

    vm.restore_previous_version()
    vm_after_restore = VaultManager(path)
    vm_after_restore.unlock("BackupTest123456!")
    check("Backups", "restore_previous_version() recupera al menos la última versión guardada",
          len(vm_after_restore.get_entries()) >= 1)

    cleanup(path)


# ============================================================
# AUDITORÍA DE CONTRASEÑAS
# ============================================================
def test_password_audit():
    entries = [
        {"site": "debil.com", "password": "123456"},
        {"site": "fuerte1.com", "password": "Xk9#mP2$vQr7!nL4"},
        {"site": "fuerte2.com", "password": "Xk9#mP2$vQr7!nL4"},  # reutilizada
        {"site": "unica.com", "password": "Zw8@bT5&hY3*dF6!"},
    ]
    report = analyze_entries(entries)

    check("Auditoría", "Detecta la contraseña débil",
          any(e["site"] == "debil.com" for e in report["weak_entries"]))
    check("Auditoría", "Detecta el grupo de contraseñas reutilizadas",
          len(report["reused_groups"]) == 1 and
          set(report["reused_groups"][0]["sites"]) == {"fuerte1.com", "fuerte2.com"})
    check("Auditoría", "No marca la contraseña única y fuerte como problema",
          not any(e["site"] == "unica.com" for e in report["weak_entries"]))


# ============================================================
# ANTI-DEBUGGING
# ============================================================
def test_anti_debugging():
    result_clean = anti_debug.check(derivation_seconds=1.5)
    check("Anti-debugging", "Entorno limpio no genera falsos positivos",
          result_clean["suspicious"] is False)

    fake_proc = MagicMock()
    fake_proc.info = {"name": "x64dbg.exe"}
    with patch("psutil.process_iter", return_value=[fake_proc]):
        result_proc = anti_debug.check()
    check("Anti-debugging", "Detecta un debugger conocido corriendo en el sistema (x64dbg.exe)",
          result_proc["suspicious"] and "x64dbg" in result_proc["reasons"][0])

    result_timing = anti_debug.check(derivation_seconds=60.0)
    check("Anti-debugging", "Detecta timing anómalo en la derivación (posible single-stepping)",
          result_timing["suspicious"])

    result_normal_timing = anti_debug.check(derivation_seconds=2.0)
    check("Anti-debugging", "Timing normal (2s) NO dispara falso positivo",
          not result_normal_timing["suspicious"])


# ============================================================
# GENERADOR DE CONTRASEÑAS
# ============================================================
def test_password_generator():
    passwords = [generate_password(20) for _ in range(20)]
    check("Generador", "Genera contraseñas únicas (20/20 distintas)",
          len(set(passwords)) == 20)
    check("Generador", "Las contraseñas generadas se clasifican como fuertes",
          all(estimate_strength(p) in ("Fuerte", "Muy fuerte") for p in passwords))

    short_password_rejected = False
    try:
        generate_password(4)
    except ValueError:
        short_password_rejected = True
    check("Generador", "Rechaza longitudes inseguras (<8 caracteres)", short_password_rejected)


# ============================================================
# HIGIENE DE MEMORIA
# ============================================================
def test_memory_hygiene():
    path = new_temp_path()
    vm = VaultManager(path)
    vm.create_vault("MemTest123456!")
    key_was_present = vm.key is not None and any(b != 0 for b in vm.key)

    vm.lock()
    check("Higiene de memoria", "La clave no es None tras crear/desbloquear (sanity check)",
          key_was_present)
    check("Higiene de memoria", "lock() borra la referencia a la clave de la instancia",
          vm.key is None)
    check("Higiene de memoria", "lock() borra las entradas y el secreto TOTP de memoria",
          vm.entries == [] and vm.totp_secret is None)

    cleanup(path)


# ============================================================
# CLIPBOARD
# ============================================================
# NOTA: el auto-clear del portapapeles no se prueba acá de forma automática
# porque depende de un gestor de portapapeles real del sistema operativo
# (en Linux headless/CI, xclip/xsel se comportan de forma poco confiable
# sin un entorno de escritorio real). Verificalo manualmente:
#   1. Copiá una contraseña con el botón "Password" de una entrada.
#   2. Pegala en cualquier lado (debería pegar bien).
#   3. Esperá 20 segundos y probá pegar de nuevo (debería estar vacío).


# ============================================================
# EJECUTAR TODO Y REPORTAR
# ============================================================
def main():
    tests = [
        test_confidentiality,
        test_integrity,
        test_authentication,
        test_brute_force_protection,
        test_2fa,
        test_backups_and_recovery,
        test_password_audit,
        test_anti_debugging,
        test_password_generator,
        test_memory_hygiene,
    ]

    for t in tests:
        try:
            t()
        except Exception as e:
            check(t.__name__, "ERROR INESPERADO durante la prueba", False, str(e))

    categorias = {}
    for cat, name, passed, detail in RESULTS:
        categorias.setdefault(cat, []).append((name, passed, detail))

    total = len(RESULTS)
    passed_count = sum(1 for _, _, p, _ in RESULTS if p is True)
    skipped_count = sum(1 for _, _, p, _ in RESULTS if p is None)
    failed_count = total - passed_count - skipped_count

    print("=" * 70)
    print("REPORTE DE PRUEBAS DE SEGURIDAD — PassVault")
    print("=" * 70)

    for cat, items in categorias.items():
        print(f"\n[{cat}]")
        for name, passed, detail in items:
            symbol = "✓ PASS" if passed is True else ("⊘ SKIP" if passed is None else "✗ FAIL")
            print(f"  {symbol}  {name}" + (f"  ({detail})" if detail and passed is not True else ""))

    print("\n" + "=" * 70)
    print(f"TOTAL: {total} pruebas | {passed_count} pasaron | {failed_count} fallaron | {skipped_count} omitidas")
    print("=" * 70)

    if failed_count > 0:
        sys.exit(1)


if __name__ == "__main__":
    main()