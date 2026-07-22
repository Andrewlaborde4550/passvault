"""
login_screen.py
----------------
Pantalla inicial: si no existe vault, pide crear una master password
(con confirmación y validación de fortaleza). Si ya existe, pide
la master password para desbloquear.
"""

import threading
import customtkinter as ctk
from vault_manager import WrongPasswordError, VaultError
from utils.lockout_manager import LockoutManager
from utils.audit_log import AuditLogger
from utils import anti_debug
from gui.confirm_dialog import ConfirmDialog


class LoginScreen(ctk.CTkFrame):
    def __init__(self, master, vault_manager, on_created, on_unlocked):
        super().__init__(master, fg_color="transparent")
        self.vault_manager = vault_manager
        self.on_created = on_created
        self.on_unlocked = on_unlocked
        self.is_new_vault = not vault_manager.vault_exists()
        self.lockout = LockoutManager(vault_manager.vault_path)
        self.audit = AuditLogger(vault_manager.vault_path)
        self._countdown_job = None

        self._build_ui()
        if not self.is_new_vault:
            self._check_lockout()

    def _build_ui(self):
        container = ctk.CTkFrame(self, corner_radius=16)
        container.place(relx=0.5, rely=0.5, anchor="center")

        title = "Crear tu Vault" if self.is_new_vault else "Desbloquear Vault"
        subtitle = (
            "Elige una master password fuerte. No hay forma de recuperarla si la olvidas."
            if self.is_new_vault
            else "Ingresa tu master password"
        )

        ctk.CTkLabel(container, text="🔒 PassVault", font=ctk.CTkFont(size=26, weight="bold")).pack(pady=(30, 5), padx=60)
        ctk.CTkLabel(container, text=title, font=ctk.CTkFont(size=16)).pack(pady=(0, 4))
        ctk.CTkLabel(container, text=subtitle, font=ctk.CTkFont(size=12), text_color="gray").pack(pady=(0, 20))

        self.password_entry = ctk.CTkEntry(container, placeholder_text="Master password", show="•", width=280, height=38)
        self.password_entry.pack(pady=6, padx=40)
        self.password_entry.bind("<Return>", lambda e: self._handle_submit())

        if self.is_new_vault:
            self.confirm_entry = ctk.CTkEntry(container, placeholder_text="Confirmar master password", show="•", width=280, height=38)
            self.confirm_entry.pack(pady=6, padx=40)
            self.confirm_entry.bind("<Return>", lambda e: self._handle_submit())

            self.strength_label = ctk.CTkLabel(container, text="", font=ctk.CTkFont(size=11))
            self.strength_label.pack(pady=(2, 0))
            self.password_entry.bind("<KeyRelease>", self._update_strength)

        self.error_label = ctk.CTkLabel(container, text="", text_color="#ff5555", font=ctk.CTkFont(size=12))
        self.error_label.pack(pady=(8, 0))

        btn_text = "Crear Vault" if self.is_new_vault else "Desbloquear"
        self.submit_btn = ctk.CTkButton(container, text=btn_text, width=280, height=38, command=self._handle_submit)
        self.submit_btn.pack(pady=(15, 30), padx=40)

        self.password_entry.focus()

    def _update_strength(self, event=None):
        pwd = self.password_entry.get()
        if len(pwd) == 0:
            self.strength_label.configure(text="")
            return
        score = self._password_score(pwd)
        labels = ["Muy débil ⚠️", "Débil", "Aceptable", "Fuerte", "Muy fuerte ✓"]
        colors = ["#ff5555", "#ff8855", "#ffcc55", "#88cc55", "#55cc88"]
        idx = min(score, 4)
        self.strength_label.configure(text=labels[idx], text_color=colors[idx])

    @staticmethod
    def _password_score(pwd: str) -> int:
        score = 0
        if len(pwd) >= 12:
            score += 1
        if len(pwd) >= 16:
            score += 1
        if any(c.isupper() for c in pwd) and any(c.islower() for c in pwd):
            score += 1
        if any(c.isdigit() for c in pwd):
            score += 1
        if any(not c.isalnum() for c in pwd):
            score += 1
        return score

    def _handle_submit(self):
        self.error_label.configure(text="")
        password = self.password_entry.get()

        if self.is_new_vault:
            confirm = self.confirm_entry.get()
            if len(password) < 12:
                self.error_label.configure(text="Mínimo 12 caracteres para la master password.")
                return
            if password != confirm:
                self.error_label.configure(text="Las contraseñas no coinciden.")
                return
            self._run_in_background(
                work=lambda: self.vault_manager.create_vault(password),
                on_success=self._on_created_wrapper,
                on_error=lambda e: self.error_label.configure(text=str(e)),
                busy_text="Creando vault...",
            )
        else:
            if self.lockout.seconds_remaining() > 0:
                return  # el botón ya debería estar deshabilitado, doble chequeo

            def on_success():
                self.lockout.register_success()
                self.audit.log("unlock_success")
                if not self._check_debug_signals():
                    return
                self.on_unlocked()

            def on_error(e):
                if isinstance(e, WrongPasswordError):
                    self.audit.log("unlock_failed")
                    delay = self.lockout.register_failure()
                    if delay > 0:
                        self._check_lockout()
                    else:
                        remaining = self.lockout.attempts_before_lockout()
                        self.error_label.configure(
                            text=f"Master password incorrecta. Te quedan {remaining} intento(s) antes de una espera."
                        )
                else:
                    self.error_label.configure(text=str(e))

            self._run_in_background(
                work=lambda: self.vault_manager.unlock(password),
                on_success=on_success,
                on_error=on_error,
                busy_text="Verificando...",
            )

    def _on_created_wrapper(self):
        self.audit.log("vault_created")
        self.on_created()

    def _run_in_background(self, work, on_success, on_error, busy_text):
        """
        Corre `work` (que internamente hace la derivación Argon2id, ~1-2s)
        en un hilo aparte para no congelar la ventana, y reenvía el resultado
        al hilo principal de Tk con `after(0, ...)`, que es la única forma
        segura de tocar widgets de Tk desde fuera del hilo principal.
        """
        self.submit_btn.configure(state="disabled", text=busy_text)
        self.password_entry.configure(state="disabled")
        if hasattr(self, "confirm_entry"):
            self.confirm_entry.configure(state="disabled")

        def worker():
            try:
                work()
                self.after(0, lambda: self._finish_background(on_success, on_error, None))
            except Exception as e:
                # Python borra automáticamente la variable de un "except ... as e" al
                # salir del bloque, así que hay que copiarla a una variable normal
                # ANTES de programar el callback asíncrono, o el lambda explota con
                # NameError cuando finalmente se ejecuta.
                err = e
                self.after(0, lambda err=err: self._finish_background(on_success, on_error, err))

        threading.Thread(target=worker, daemon=True).start()

    def _finish_background(self, on_success, on_error, error):
        if not self.winfo_exists():
            return  # la pantalla ya cambió (ej. tras crear el vault) antes de que volviera el hilo

        original_text = "Crear Vault" if self.is_new_vault else "Desbloquear"
        self.submit_btn.configure(state="normal", text=original_text)
        self.password_entry.configure(state="normal")
        if hasattr(self, "confirm_entry"):
            self.confirm_entry.configure(state="normal")

        if error is None:
            on_success()
        else:
            on_error(error)

    def _check_debug_signals(self) -> bool:
        """
        Corre justo después de desbloquear, que es el momento en que la clave
        entra a memoria por primera vez. Retorna True si está OK continuar,
        False si el usuario decidió cancelar (y ya se volvió a bloquear el vault).

        Nota: esto es una capa de fricción adicional, no una protección real —
        ver el docstring de utils/anti_debug.py para el detalle honesto de
        sus limitaciones.
        """
        result = anti_debug.check(derivation_seconds=self.vault_manager.last_derivation_seconds)
        if not result["suspicious"]:
            return True

        self.audit.log("debugger_detected", detail="; ".join(result["reasons"]))
        proceed = ConfirmDialog.ask(
            self,
            title="Actividad sospechosa detectada",
            message="Detectamos posibles señales de debugging o memory-dumping:\n\n"
                    + "\n".join(f"• {r}" for r in result["reasons"])
                    + "\n\nEsto podría exponer datos del vault en memoria. ¿Continuar de todas formas?",
            confirm_text="Continuar igual",
            cancel_text="Cancelar y bloquear",
            confirm_color="#a83232",
            confirm_hover="#7a2424",
            icon="🛡",
        )
        if not proceed:
            self.vault_manager.lock()
            return False
        return True

    def _check_lockout(self):
        """Si hay un lockout activo, deshabilita el formulario y muestra un contador regresivo."""
        remaining = self.lockout.seconds_remaining()
        if remaining <= 0:
            self.submit_btn.configure(state="normal", text="Desbloquear")
            self.password_entry.configure(state="normal")
            if self._countdown_job:
                self.after_cancel(self._countdown_job)
                self._countdown_job = None
            return

        self.submit_btn.configure(state="disabled", text=f"Esperá {remaining}s")
        self.password_entry.configure(state="disabled")
        self.error_label.configure(text="Demasiados intentos fallidos. Espera antes de volver a intentar.")
        self._countdown_job = self.after(1000, self._check_lockout)