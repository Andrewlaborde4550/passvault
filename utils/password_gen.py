"""
password_gen.py
----------------
Generador de contraseñas usando `secrets` (no `random`), que usa el
generador de números aleatorios del sistema operativo, seguro para
propósitos criptográficos.
"""

import secrets
import string


AMBIGUOUS_CHARS = "Il1O0"


def generate_password(
    length: int = 20,
    use_upper: bool = True,
    use_lower: bool = True,
    use_digits: bool = True,
    use_symbols: bool = True,
    avoid_ambiguous: bool = True,
) -> str:
    if length < 8:
        raise ValueError("La longitud mínima recomendada es 8 caracteres.")

    pools = []
    if use_lower:
        pools.append(string.ascii_lowercase)
    if use_upper:
        pools.append(string.ascii_uppercase)
    if use_digits:
        pools.append(string.digits)
    if use_symbols:
        pools.append("!@#$%^&*()-_=+[]{};:,.<>?")

    if not pools:
        raise ValueError("Debe seleccionar al menos un tipo de carácter.")

    alphabet = "".join(pools)
    if avoid_ambiguous:
        alphabet = "".join(c for c in alphabet if c not in AMBIGUOUS_CHARS)

    # Garantiza al menos un carácter de cada pool seleccionado
    password_chars = [secrets.choice(p) for p in pools]
    while len(password_chars) < length:
        password_chars.append(secrets.choice(alphabet))

    # Mezcla segura (Fisher-Yates usando secrets)
    for i in range(len(password_chars) - 1, 0, -1):
        j = secrets.randbelow(i + 1)
        password_chars[i], password_chars[j] = password_chars[j], password_chars[i]

    return "".join(password_chars[:length])


def estimate_strength(password: str) -> str:
    """Estimación simple de entropía para mostrar feedback al usuario."""
    pool_size = 0
    if any(c.islower() for c in password):
        pool_size += 26
    if any(c.isupper() for c in password):
        pool_size += 26
    if any(c.isdigit() for c in password):
        pool_size += 10
    if any(not c.isalnum() for c in password):
        pool_size += 32

    if pool_size == 0:
        return "Muy débil"

    import math
    entropy = len(password) * math.log2(pool_size)

    if entropy < 40:
        return "Débil"
    elif entropy < 60:
        return "Moderada"
    elif entropy < 80:
        return "Fuerte"
    else:
        return "Muy fuerte"