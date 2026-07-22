"""
security.py
------------
Timer de inactividad: si el usuario no interactúa con la app
en N segundos, se dispara un callback (normalmente lock() del vault).
"""

import threading


class InactivityMonitor:
    def __init__(self, timeout_seconds: int, on_timeout):
        self.timeout_seconds = timeout_seconds
        self.on_timeout = on_timeout
        self._timer = None
        self._lock = threading.Lock()
        self._active = False

    def start(self):
        self._active = True
        self._reset_timer()

    def stop(self):
        self._active = False
        with self._lock:
            if self._timer:
                self._timer.cancel()

    def reset(self):
        """Llamar en cada interacción del usuario (click, tecla, etc.)."""
        if self._active:
            self._reset_timer()

    def _reset_timer(self):
        with self._lock:
            if self._timer:
                self._timer.cancel()
            self._timer = threading.Timer(self.timeout_seconds, self._trigger)
            self._timer.daemon = True
            self._timer.start()

    def _trigger(self):
        if self._active:
            self.on_timeout()