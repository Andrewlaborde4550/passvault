"""
main.py
-------
Punto de entrada de PassVault.

Flujo:
1. Muestra LoginScreen (crear vault o desbloquear).
2. Al desbloquear, muestra MainScreen con las entradas.
3. Un InactivityMonitor bloquea automáticamente el vault tras
   INACTIVITY_TIMEOUT segundos sin interacción del usuario.
4. Al bloquear, se destruye MainScreen y se vuelve a LoginScreen,
   y la clave se borra de memoria (vault_manager.lock()).
"""

import os
import sys
import customtkinter as ctk

from vault_manager import VaultManager
from gui.login_screen import LoginScreen
from gui.main_screen import MainScreen
from gui.totp_screen import TOTPSetupScreen, TOTPVerifyScreen
from utils.security import InactivityMonitor

VAULT_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "vault.enc")
INACTIVITY_TIMEOUT_SECONDS = 180  # 3 minutos


def resource_path(relative_path: str) -> str:
    """
    Resuelve la ruta a un recurso (ej. el ícono) tanto en desarrollo como
    empaquetado con PyInstaller --onefile, que extrae los datos agregados
    con --add-data a una carpeta temporal distinta (sys._MEIPASS).
    """
    base_path = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base_path, relative_path)


class PassVaultApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("green")

        self.title("PassVault")
        self.geometry("760x640")
        self.minsize(700, 520)
        self._set_window_icon()

        self.vault_manager = VaultManager(VAULT_PATH)
        self.current_screen = None

        self.inactivity_monitor = InactivityMonitor(
            timeout_seconds=INACTIVITY_TIMEOUT_SECONDS,
            on_timeout=self._auto_lock,
        )

        # Detecta actividad global del usuario para resetear el timer de auto-lock
        self.bind_all("<Any-KeyPress>", lambda e: self.inactivity_monitor.reset())
        self.bind_all("<Any-Button>", lambda e: self.inactivity_monitor.reset())

        self.protocol("WM_DELETE_WINDOW", self._on_close)

        self._show_login()

    def _set_window_icon(self):
        """
        En Windows, .ico vía iconbitmap da el mejor resultado (barra de tareas,
        Alt+Tab, título de ventana). En otros sistemas .ico no siempre funciona,
        así que probamos con .png vía iconphoto como respaldo. Si ambos fallan
        (ej. falta el archivo), la app sigue funcionando igual, solo sin ícono
        personalizado — nunca debe tumbar el arranque por esto.
        """
        ico_path = resource_path(os.path.join("assets", "icon.ico"))
        png_path = resource_path(os.path.join("assets", "icon.png"))
        try:
            if sys.platform == "win32" and os.path.exists(ico_path):
                self.iconbitmap(ico_path)
                return
        except Exception:
            pass
        try:
            if os.path.exists(png_path):
                import tkinter as tk
                photo = tk.PhotoImage(file=png_path)
                self.iconphoto(True, photo)
                self._icon_photo_ref = photo  # evitar que el garbage collector se lo lleve
        except Exception:
            pass

    def _show_login(self):
        self.inactivity_monitor.stop()
        self._clear_screen()
        self.current_screen = LoginScreen(
            self, self.vault_manager,
            on_created=self._show_totp_setup,
            on_unlocked=self._after_unlock,
        )
        self.current_screen.pack(fill="both", expand=True)

    def _show_totp_setup(self):
        """Tras crear un vault nuevo, ofrece activar 2FA antes de entrar."""
        self._clear_screen()
        self.current_screen = TOTPSetupScreen(self, self.vault_manager, on_done=self._render_main_screen)
        self.current_screen.pack(fill="both", expand=True)

    def _after_unlock(self):
        """Tras desbloquear con la master password, exige 2FA si está activado."""
        if self.vault_manager.totp_enabled:
            self._show_totp_verify()
        else:
            self._render_main_screen()

    def _show_totp_verify(self):
        self._clear_screen()
        self.current_screen = TOTPVerifyScreen(
            self, self.vault_manager,
            on_verified=self._render_main_screen,
            on_cancel=self._manual_lock,
        )
        self.current_screen.pack(fill="both", expand=True)

    def _render_main_screen(self):
        self._clear_screen()
        self.current_screen = MainScreen(self, self.vault_manager, on_lock=self._manual_lock)
        self.current_screen.pack(fill="both", expand=True)
        self.inactivity_monitor.start()

    def _clear_screen(self):
        if self.current_screen is not None:
            # Algunas pantallas (MainScreen, TOTPVerifyScreen) atan atajos de teclado
            # a la ventana raíz y necesitan desatarlos explícitamente antes de destruirse,
            # o el atajo queda intentando llamar a una pantalla que ya no existe.
            cleanup = getattr(self.current_screen, "cleanup_shortcuts", None)
            if callable(cleanup):
                cleanup()
            self.current_screen.destroy()
            self.current_screen = None

    def _manual_lock(self):
        self.vault_manager.lock()
        self._show_login()

    def _auto_lock(self):
        # Se ejecuta desde un hilo del Timer; hay que reenviarlo al hilo de la GUI
        self.after(0, self._manual_lock)

    def _on_close(self):
        self.vault_manager.lock()
        self.destroy()


if __name__ == "__main__":
    app = PassVaultApp()
    app.mainloop()