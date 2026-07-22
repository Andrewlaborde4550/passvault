"""
totp.py
-------
2FA basado en TOTP (RFC 6238) usando pyotp. Compatible con Google
Authenticator, Authy, Microsoft Authenticator, etc.

Nota de diseño: el secreto TOTP se guarda cifrado DENTRO del vault
(mismo AES-256-GCM que las entradas), no en texto plano en ningún
archivo. Esto significa que el 2FA es una segunda verificación real
para quien solo capturó la master password (ej. keylogger, shoulder
surfing) pero no tiene acceso físico al dispositivo con la app
autenticadora — que es el escenario que un 2FA está pensado para cubrir.
"""

import pyotp

ISSUER_NAME = "PassVault"


def generate_secret() -> str:
    """Genera un secreto TOTP aleatorio en Base32 (compatible con cualquier app autenticadora)."""
    return pyotp.random_base32()


def get_provisioning_uri(secret: str, account_name: str = "vault") -> str:
    """URI otpauth:// estándar, por si el usuario quiere escanearlo como QR más adelante."""
    return pyotp.totp.TOTP(secret).provisioning_uri(name=account_name, issuer_name=ISSUER_NAME)


def verify_code(secret: str, code: str) -> bool:
    """
    Verifica un código de 6 dígitos contra el secreto.
    valid_window=1 acepta el código del intervalo anterior y siguiente (±30s)
    para tolerar pequeños desfaces de reloj entre el teléfono y el equipo.
    """
    if not secret or not code:
        return False
    code = code.strip().replace(" ", "")
    if not code.isdigit() or len(code) != 6:
        return False
    totp = pyotp.TOTP(secret)
    return totp.verify(code, valid_window=1)


def format_secret_for_display(secret: str) -> str:
    """Formatea el secreto en grupos de 4 para que sea más fácil de transcribir a mano."""
    return " ".join(secret[i:i + 4] for i in range(0, len(secret), 4))
