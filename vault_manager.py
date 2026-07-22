"""
vault_manager.py
-----------------
Maneja el archivo del vault (vault.enc), incluyendo:
- Creación inicial (setup de master password)
- Desbloqueo (unlock) y verificación
- CRUD de entradas (sitio, usuario, contraseña, notas)
- Serialización JSON -> cifrado -> disco

Formato del archivo vault.enc (binario):
[1 byte versión][16 bytes salt][12 bytes nonce][ciphertext+tag...]

El contenido cifrado es un JSON con la estructura:
{
    "entries": [
        {"id": "...", "site": "...", "username": "...", "password": "...",
         "notes": "...", "created_at": "...", "updated_at": "..."}
    ],
    "check": "VAULT_OK"   # valor conocido para verificar que la clave es correcta
}
"""

import os
import json
import uuid
import shutil
import time
from datetime import datetime, timezone
from cryptography.exceptions import InvalidTag

from crypto_engine import CryptoEngine, SALT_LENGTH

VAULT_VERSION = b"\x01"
CHECK_VALUE = "VAULT_OK"


class VaultError(Exception):
    """Error genérico de operaciones del vault."""
    pass


class WrongPasswordError(VaultError):
    """La master password ingresada es incorrecta o el archivo fue manipulado."""
    pass


class VaultManager:
    def __init__(self, vault_path: str):
        self.vault_path = vault_path
        self.key = None          # clave derivada en memoria (bytearray)
        self.entries = []        # lista de entradas descifradas en memoria
        self.totp_enabled = False
        self.totp_secret = None  # secreto Base32, solo en memoria mientras está desbloqueado
        self.last_derivation_seconds = None  # cuánto tardó la última derivación Argon2id (para detectar single-stepping)
        self._salt = None
        self._unlocked = False

    # ---------------- Estado del vault en disco ----------------

    def vault_exists(self) -> bool:
        return os.path.exists(self.vault_path)

    # ---------------- Creación / setup inicial ----------------

    def create_vault(self, master_password: str):
        """Crea un vault nuevo con la master password dada."""
        if self.vault_exists():
            raise VaultError("Ya existe un vault en esta ruta.")

        salt = CryptoEngine.generate_salt()
        t0 = time.monotonic()
        key = CryptoEngine.derive_key(master_password, salt)
        self.last_derivation_seconds = time.monotonic() - t0

        self._salt = salt
        self.key = bytearray(key)
        self.entries = []
        self.totp_enabled = False
        self.totp_secret = None
        self._unlocked = True
        self._persist()

    # ---------------- Desbloqueo ----------------

    def unlock(self, master_password: str):
        """
        Intenta desbloquear el vault con la master password dada.
        Lanza WrongPasswordError si falla la autenticación o el archivo
        fue manipulado (falla la verificación GCM).
        """
        if not self.vault_exists():
            raise VaultError("No existe un vault en esta ruta.")

        with open(self.vault_path, "rb") as f:
            raw = f.read()

        version = raw[0:1]
        salt = raw[1:1 + SALT_LENGTH]
        encrypted_blob = raw[1 + SALT_LENGTH:]

        if version != VAULT_VERSION:
            raise VaultError("Versión de vault no soportada.")

        t0 = time.monotonic()
        key = CryptoEngine.derive_key(master_password, salt)
        self.last_derivation_seconds = time.monotonic() - t0

        try:
            plaintext = CryptoEngine.decrypt(encrypted_blob, key)
        except InvalidTag:
            raise WrongPasswordError("Master password incorrecta o vault corrupto/manipulado.")

        data = json.loads(plaintext.decode("utf-8"))

        if data.get("check") != CHECK_VALUE:
            raise WrongPasswordError("Verificación de integridad fallida.")

        self._salt = salt
        self.key = bytearray(key)
        self.entries = data.get("entries", [])
        self.totp_enabled = data.get("totp_enabled", False)
        self.totp_secret = data.get("totp_secret")
        self._unlocked = True

    def lock(self):
        """Bloquea el vault y borra la clave y las entradas de memoria."""
        if self.key:
            CryptoEngine.zero_memory(self.key)
        self.key = None
        self.entries = []
        self.totp_enabled = False
        self.totp_secret = None
        self._unlocked = False

    def is_unlocked(self) -> bool:
        return self._unlocked

    # ---------------- Persistencia ----------------

    def _persist(self):
        """Serializa las entradas actuales, cifra, y escribe a disco de forma atómica."""
        if not self._unlocked:
            raise VaultError("El vault está bloqueado.")

        payload = {
            "entries": self.entries,
            "check": CHECK_VALUE,
            "totp_enabled": self.totp_enabled,
            "totp_secret": self.totp_secret,
        }
        plaintext = json.dumps(payload).encode("utf-8")
        encrypted_blob = CryptoEngine.encrypt(plaintext, bytes(self.key))

        raw = VAULT_VERSION + self._salt + encrypted_blob

        # Escritura atómica: escribe a un archivo temporal y luego renombra,
        # así evitamos corromper el vault si el programa se cierra a mitad de escritura.
        tmp_path = self.vault_path + ".tmp"

        # Antes de sobrescribir, guarda la versión actual como respaldo de un solo nivel.
        # Esto protege contra errores del usuario (ej. borrar una entrada por accidente)
        # dándole un "deshacer" de la última versión guardada, no del historial completo.
        if os.path.exists(self.vault_path):
            try:
                shutil.copy2(self.vault_path, self.vault_path + ".bak")
            except OSError:
                pass  # el respaldo es best-effort, no debe bloquear el guardado principal

        with open(tmp_path, "wb") as f:
            f.write(raw)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_path, self.vault_path)

    # ---------------- CRUD de entradas ----------------

    DEFAULT_CATEGORY = "General"

    def _normalize_category(self, raw: str) -> str:
        """
        Si ya existe una categoría con el mismo nombre salvo mayúsculas/minúsculas
        (ej. escribiste 'trabajo' pero ya existía 'Trabajo'), reusa la que ya existe
        en vez de crear una nueva casi-idéntica.
        """
        raw = (raw or "").strip()
        if not raw:
            return self.DEFAULT_CATEGORY
        for existing in self.get_categories():
            if existing.lower() == raw.lower():
                return existing
        return raw

    def add_entry(self, site: str, username: str, password: str, notes: str = "", category: str = "") -> dict:
        self._require_unlocked()
        now = datetime.now(timezone.utc).isoformat()
        entry = {
            "id": str(uuid.uuid4()),
            "site": site,
            "username": username,
            "password": password,
            "notes": notes,
            "category": self._normalize_category(category),
            "created_at": now,
            "updated_at": now,
        }
        self.entries.append(entry)
        self._persist()
        return entry

    def update_entry(self, entry_id: str, **fields):
        self._require_unlocked()
        if "category" in fields and fields["category"] is not None:
            fields["category"] = self._normalize_category(fields["category"])
        for entry in self.entries:
            if entry["id"] == entry_id:
                entry.update({k: v for k, v in fields.items() if v is not None})
                entry.setdefault("category", self.DEFAULT_CATEGORY)
                entry["updated_at"] = datetime.now(timezone.utc).isoformat()
                self._persist()
                return entry
        raise VaultError("Entrada no encontrada.")

    def delete_entry(self, entry_id: str):
        self._require_unlocked()
        before = len(self.entries)
        self.entries = [e for e in self.entries if e["id"] != entry_id]
        if len(self.entries) == before:
            raise VaultError("Entrada no encontrada.")
        self._persist()

    def get_categories(self) -> list:
        """Categorías existentes entre las entradas actuales, ordenadas alfabéticamente."""
        self._require_unlocked()
        cats = {e.get("category", self.DEFAULT_CATEGORY) for e in self.entries}
        return sorted(cats)

    def get_entries(self, search: str = "", category: str = "") -> list:
        self._require_unlocked()
        results = self.entries
        if category:
            results = [e for e in results if e.get("category", self.DEFAULT_CATEGORY) == category]
        if not search:
            return list(results)
        search_lower = search.lower()
        return [
            e for e in results
            if search_lower in e["site"].lower() or search_lower in e["username"].lower()
        ]

    def change_master_password(self, new_master_password: str):
        """Re-cifra todo el vault con una nueva master password (nuevo salt + nueva clave)."""
        self._require_unlocked()
        new_salt = CryptoEngine.generate_salt()
        new_key = CryptoEngine.derive_key(new_master_password, new_salt)

        old_key = self.key
        self._salt = new_salt
        self.key = bytearray(new_key)
        self._persist()

        if old_key:
            CryptoEngine.zero_memory(old_key)

    def has_previous_version(self) -> bool:
        return os.path.exists(self.vault_path + ".bak")

    def restore_previous_version(self):
        """
        Restaura la última versión respaldada automáticamente antes del guardado
        más reciente. Requiere volver a desbloquear después, porque el contenido
        en disco cambió y ya no coincide con lo que hay en memoria.
        """
        bak_path = self.vault_path + ".bak"
        if not os.path.exists(bak_path):
            raise VaultError("No hay una versión anterior disponible para restaurar.")
        shutil.copy2(bak_path, self.vault_path)

    # ---------------- 2FA / TOTP ----------------

    def enable_totp(self, secret: str):
        self._require_unlocked()
        self.totp_enabled = True
        self.totp_secret = secret
        self._persist()

    def disable_totp(self):
        self._require_unlocked()
        self.totp_enabled = False
        self.totp_secret = None
        self._persist()

    # ---------------- Backup ----------------

    def export_backup(self, destination_path: str):
        """
        Copia el archivo del vault (sigue cifrado con AES-256-GCM tal cual está
        en disco) a la ruta indicada. El backup requiere la misma master password
        para poder abrirse — no es una copia en texto plano.
        """
        if not self.vault_exists():
            raise VaultError("No hay vault para respaldar.")
        shutil.copy2(self.vault_path, destination_path)

    def _require_unlocked(self):
        if not self._unlocked:
            raise VaultError("El vault está bloqueado.")