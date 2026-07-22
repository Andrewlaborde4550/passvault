"""
clipboard.py
------------
Copia texto sensible al portapapeles y lo borra automáticamente
después de N segundos, para minimizar exposición si el usuario
olvida limpiarlo manualmente.
"""

import threading
import pyperclip


class SecureClipboard:
    def __init__(self, clear_after_seconds: int = 20):
        self.clear_after_seconds = clear_after_seconds
        self._timer = None
        self._lock = threading.Lock()

    def copy(self, text: str):
        with self._lock:
            if self._timer:
                self._timer.cancel()

            pyperclip.copy(text)

            self._timer = threading.Timer(self.clear_after_seconds, self._clear, args=(text,))
            self._timer.daemon = True
            self._timer.start()

    def _clear(self, expected_text: str):
        with self._lock:
            # Solo limpia si el portapapeles sigue teniendo lo que copiamos
            # (evita borrar algo distinto que el usuario haya copiado después)
            try:
                if pyperclip.paste() == expected_text:
                    pyperclip.copy("")
            except Exception:
                pass