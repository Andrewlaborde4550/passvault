"""
lockout_manager.py
-------------------
Rate limiting contra fuerza bruta en el desbloqueo del vault.

Diseño:
- Los primeros FREE_ATTEMPTS intentos fallidos no generan espera.
- A partir de ahí, cada intento fallido dobla el tiempo de espera
  (5s, 10s, 20s, 40s... hasta un tope de MAX_DELAY_SECONDS).
- El estado se guarda en un archivo separado del vault (<vault>.lockout),
  en texto plano — no hace falta cifrarlo porque solo contiene contadores
  y timestamps, ningún dato sensible.

Limitación honesta: como el archivo de lockout vive junto al vault,
un atacante con acceso al filesystem podría borrarlo para resetear el
contador. Esto protege contra fuerza bruta *interactiva* a través de la
GUI (que es el vector real para alguien con acceso físico/remoto al
equipo mientras la app corre), no contra un atacante que ya tiene
control total del filesystem — ese caso ya lo cubre Argon2id, que hace
cada intento offline costoso sin importar cuántos se hagan.
"""

import os
import json
from datetime import datetime, timedelta, timezone

FREE_ATTEMPTS = 3
BASE_DELAY_SECONDS = 5
MAX_DELAY_SECONDS = 300  # 5 minutos


class LockoutManager:
    def __init__(self, vault_path: str):
        self.state_path = vault_path + ".lockout"

    def _load(self) -> dict:
        if not os.path.exists(self.state_path):
            return {"failed_attempts": 0, "locked_until": None}
        try:
            with open(self.state_path, "r") as f:
                return json.load(f)
        except (json.JSONDecodeError, OSError):
            return {"failed_attempts": 0, "locked_until": None}

    def _save(self, state: dict):
        with open(self.state_path, "w") as f:
            json.dump(state, f)

    def seconds_remaining(self) -> int:
        """Cuántos segundos faltan para poder intentar de nuevo (0 si no hay lockout activo)."""
        state = self._load()
        locked_until = state.get("locked_until")
        if not locked_until:
            return 0
        remaining = (datetime.fromisoformat(locked_until) - datetime.now(timezone.utc)).total_seconds()
        return max(0, int(remaining))

    def attempts_before_lockout(self) -> int:
        """Cuántos intentos libres quedan antes de que empiece a haber espera."""
        state = self._load()
        used = state.get("failed_attempts", 0)
        return max(0, FREE_ATTEMPTS - used)

    def register_failure(self) -> int:
        """Registra un intento fallido. Retorna los segundos de espera resultantes (0 si aún no aplica)."""
        state = self._load()
        state["failed_attempts"] = state.get("failed_attempts", 0) + 1
        attempts = state["failed_attempts"]

        delay = 0
        if attempts > FREE_ATTEMPTS:
            delay = min(BASE_DELAY_SECONDS * (2 ** (attempts - FREE_ATTEMPTS - 1)), MAX_DELAY_SECONDS)
            locked_until = datetime.now(timezone.utc) + timedelta(seconds=delay)
            state["locked_until"] = locked_until.isoformat()

        self._save(state)
        return delay

    def register_success(self):
        """Resetea el contador tras un desbloqueo exitoso."""
        self._save({"failed_attempts": 0, "locked_until": None})