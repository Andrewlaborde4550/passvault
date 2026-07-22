"""
crypto_engine.py
-----------------
Núcleo criptográfico del gestor de contraseñas.

Diseño:
- Derivación de clave: Argon2id (resistente a ataques con GPU/ASIC, ganador del PHC 2015)
- Cifrado: AES-256-GCM (cifrado autenticado: confidencialidad + integridad)
- Cada operación de cifrado usa un nonce único de 12 bytes (nunca se reutiliza)
- El salt de Argon2 es único por vault y se genera con os.urandom

Parámetros de Argon2id (ajustados para ~0.5-1s en hardware de consumo,
lo suficientemente costoso para frenar fuerza bruta sin frustrar al usuario):
- time_cost=4        -> iteraciones
- memory_cost=262144 -> 256 MB de RAM requerida por intento
- parallelism=4      -> hilos paralelos
"""

import os
import hmac
from argon2.low_level import hash_secret_raw, Type
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ---- Parámetros de seguridad ----
ARGON2_TIME_COST = 4
ARGON2_MEMORY_COST = 262144  # KiB = 256 MB
ARGON2_PARALLELISM = 4
KEY_LENGTH = 32  # 256 bits para AES-256
SALT_LENGTH = 16
NONCE_LENGTH = 12


class CryptoEngine:
    """Maneja la derivación de claves y el cifrado/descifrado del vault."""

    @staticmethod
    def generate_salt() -> bytes:
        """Genera un salt criptográficamente seguro, único por vault."""
        return os.urandom(SALT_LENGTH)

    @staticmethod
    def derive_key(master_password: str, salt: bytes) -> bytes:
        """
        Deriva una clave AES-256 a partir de la master password usando Argon2id.

        Argon2id es resistente tanto a ataques de canal lateral (side-channel)
        como a ataques con GPU/ASIC, a diferencia de PBKDF2 o SHA256 simple.
        """
        if not master_password:
            raise ValueError("La master password no puede estar vacía")

        key = hash_secret_raw(
            secret=master_password.encode("utf-8"),
            salt=salt,
            time_cost=ARGON2_TIME_COST,
            memory_cost=ARGON2_MEMORY_COST,
            parallelism=ARGON2_PARALLELISM,
            hash_len=KEY_LENGTH,
            type=Type.ID,  # Argon2id
        )
        return key

    @staticmethod
    def encrypt(plaintext: bytes, key: bytes) -> bytes:
        """
        Cifra datos con AES-256-GCM.
        Retorna: nonce (12 bytes) + ciphertext + tag de autenticación (incluido por AESGCM).
        """
        aesgcm = AESGCM(key)
        nonce = os.urandom(NONCE_LENGTH)
        ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data=None)
        return nonce + ciphertext

    @staticmethod
    def decrypt(encrypted_data: bytes, key: bytes) -> bytes:
        """
        Descifra datos cifrados con encrypt().
        Lanza cryptography.exceptions.InvalidTag si el vault fue manipulado
        o si la master password/clave es incorrecta.
        """
        aesgcm = AESGCM(key)
        nonce = encrypted_data[:NONCE_LENGTH]
        ciphertext = encrypted_data[NONCE_LENGTH:]
        plaintext = aesgcm.decrypt(nonce, ciphertext, associated_data=None)
        return plaintext

    @staticmethod
    def verify_key_constant_time(key1: bytes, key2: bytes) -> bool:
        """Comparación en tiempo constante para evitar ataques de timing."""
        return hmac.compare_digest(key1, key2)

    @staticmethod
    def zero_memory(data: bytearray):
        """
        Sobrescribe un bytearray en memoria con ceros.
        Nota: Python no garantiza el borrado real por el garbage collector,
        pero reduce la ventana de exposición de datos sensibles.
        Por eso usamos bytearray (mutable) en vez de bytes (inmutable)
        para las claves derivadas siempre que sea posible.
        """
        for i in range(len(data)):
            data[i] = 0