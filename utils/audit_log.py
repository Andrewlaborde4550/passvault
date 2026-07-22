"""
audit_log.py
-------------
Registro de eventos de acceso: desbloqueos exitosos/fallidos, verificaciones
de 2FA, backups exportados, restauraciones de versión anterior.

Vive en un archivo separado del vault (<vault>.audit.log), en texto plano,
por una razón deliberada: los intentos FALLIDOS de desbloqueo tienen que
poder registrarse incluso cuando todavía no tenemos la clave para
descifrar/re-cifrar el vault. El archivo solo contiene metadata de eventos
(tipo + timestamp), nunca contraseñas ni el contenido del vault.
"""

import os
import json
from datetime import datetime, timezone

MAX_EVENTS = 200


class AuditLogger:
    def __init__(self, vault_path: str):
        self.log_path = vault_path + ".audit.log"

    def _load(self) -> list:
        if not os.path.exists(self.log_path):
            return []
        try:
            with open(self.log_path, "r") as f:
                return json.load(f)
        except (json.JSONDecodeError, OSError):
            return []

    def _save(self, events: list):
        with open(self.log_path, "w") as f:
            json.dump(events[-MAX_EVENTS:], f)

    def log(self, event_type: str, detail: str = ""):
        events = self._load()
        events.append({
            "event": event_type,
            "detail": detail,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })
        self._save(events)

    def get_events(self, n: int = 50) -> list:
        """Retorna los últimos n eventos, más reciente primero."""
        events = self._load()
        return list(reversed(events[-n:]))


EVENT_LABELS = {
    "vault_created": "Vault creado",
    "unlock_success": "Desbloqueo exitoso",
    "unlock_failed": "Intento de desbloqueo fallido",
    "totp_success": "Verificación 2FA exitosa",
    "totp_failed": "Código 2FA incorrecto",
    "totp_enabled": "2FA activado",
    "totp_disabled": "2FA desactivado",
    "backup_exported": "Backup exportado",
    "previous_version_restored": "Versión anterior restaurada",
    "debugger_detected": "Posible debugger/memory-dumping detectado",
}