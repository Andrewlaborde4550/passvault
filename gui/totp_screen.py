"""
totp_screen.py
---------------
Dos pantallas:
- TOTPSetupScreen: se muestra justo después de crear un vault nuevo,
  ofreciendo activar 2FA (opcional).
- TOTPVerifyScreen: se muestra al desbloquear un vault que ya tiene
  2FA activado, pidiendo el código de 6 dígitos.
"""

import customtkinter as ctk
from utils import totp
from utils.audit_log import AuditLogger


class TOTPSetupScreen(ctk.CTkFrame):
    def __init__(self, master, vault_manager, on_done):
        super().__init__(master, fg_color="transparent")
        self.vault_manager = vault_manager
        self.on_done = on_done
        self.secret = totp.generate_secret()
        self.audit = AuditLogger(vault_manager.vault_path)
        self._build_offer_ui()

    def _build_offer_ui(self):
        for w in self.winfo_children():
            w.destroy()

        container = ctk.CTkFrame(self, corner_radius=16)
        container.place(relx=0.5, rely=0.5, anchor="center")

        ctk.CTkLabel(container, text="Vault creado ✓", font=ctk.CTkFont(size=22, weight="bold")).pack(pady=(30, 8), padx=60)
        ctk.CTkLabel(
            container,
            text="¿Querés activar verificación en dos pasos (2FA)?\nAsí, además de la master password, vas a necesitar\nun código de tu app autenticadora para entrar.",
            font=ctk.CTkFont(size=13), text_color="gray70", justify="center"
        ).pack(pady=(0, 20), padx=40)

        ctk.CTkButton(container, text="Activar 2FA (recomendado)", width=280, height=38,
                      command=self._show_setup_step).pack(pady=(0, 10), padx=40)
        ctk.CTkButton(container, text="Omitir por ahora", width=280, height=38,
                      fg_color="gray40", hover_color="gray30",
                      command=self.on_done).pack(pady=(0, 30), padx=40)

    def _show_setup_step(self):
        for w in self.winfo_children():
            w.destroy()

        container = ctk.CTkFrame(self, corner_radius=16)
        container.place(relx=0.5, rely=0.5, anchor="center")

        ctk.CTkLabel(container, text="Configurar 2FA", font=ctk.CTkFont(size=20, weight="bold")).pack(pady=(25, 6), padx=50)
        ctk.CTkLabel(
            container,
            text="1. Abrí tu app autenticadora (Google Authenticator, Authy, etc.)\n2. Agregá una cuenta nueva de forma manual\n3. Copiá esta clave:",
            font=ctk.CTkFont(size=12), text_color="gray70", justify="left"
        ).pack(pady=(0, 12), padx=30, anchor="w")

        secret_box = ctk.CTkTextbox(container, width=340, height=30, font=ctk.CTkFont(family="Courier", size=14))
        secret_box.pack(padx=30)
        secret_box.insert("1.0", totp.format_secret_for_display(self.secret))
        secret_box.configure(state="disabled")

        ctk.CTkLabel(container, text="4. Ingresá el código de 6 dígitos que te muestre la app:",
                     font=ctk.CTkFont(size=12), text_color="gray70").pack(pady=(16, 6), padx=30, anchor="w")

        self.code_entry = ctk.CTkEntry(container, width=340, height=36, placeholder_text="123456", justify="center",
                                        font=ctk.CTkFont(size=18))
        self.code_entry.pack(padx=30)
        self.code_entry.bind("<Return>", lambda e: self._confirm())

        self.error_label = ctk.CTkLabel(container, text="", text_color="#ff5555", font=ctk.CTkFont(size=12))
        self.error_label.pack(pady=(8, 0))

        btn_frame = ctk.CTkFrame(container, fg_color="transparent")
        btn_frame.pack(pady=(16, 25))
        ctk.CTkButton(btn_frame, text="Cancelar", fg_color="gray40", hover_color="gray30",
                      command=self._build_offer_ui).pack(side="left", padx=6)
        ctk.CTkButton(btn_frame, text="Confirmar y activar", command=self._confirm).pack(side="left", padx=6)

        self.code_entry.focus()

    def _confirm(self):
        code = self.code_entry.get()
        if totp.verify_code(self.secret, code):
            self.vault_manager.enable_totp(self.secret)
            self.audit.log("totp_enabled")
            self.on_done()
        else:
            self.error_label.configure(text="Código incorrecto. Verificá la hora de tu teléfono e intentá de nuevo.")


class TOTPVerifyScreen(ctk.CTkFrame):
    def __init__(self, master, vault_manager, on_verified, on_cancel):
        super().__init__(master, fg_color="transparent")
        self.vault_manager = vault_manager
        self.on_verified = on_verified
        self.on_cancel = on_cancel
        self.audit = AuditLogger(vault_manager.vault_path)
        self._build_ui()
        # Ver el comentario en MainScreen._bind_shortcuts sobre por qué esto no usa
        # bind_all ni depende del evento <Destroy> para el cleanup.
        self._shortcut_root = self.winfo_toplevel()
        self._shortcut_root.bind("<Escape>", lambda e: self.on_cancel())

    def cleanup_shortcuts(self):
        """Debe llamarse ANTES de destruir esta pantalla (ver main.py: _clear_screen)."""
        try:
            self._shortcut_root.unbind("<Escape>")
        except Exception:
            pass

    def _build_ui(self):
        container = ctk.CTkFrame(self, corner_radius=16)
        container.place(relx=0.5, rely=0.5, anchor="center")

        ctk.CTkLabel(container, text="Verificación en dos pasos", font=ctk.CTkFont(size=20, weight="bold")).pack(pady=(30, 6), padx=50)
        ctk.CTkLabel(container, text="Ingresá el código de tu app autenticadora",
                     font=ctk.CTkFont(size=12), text_color="gray70").pack(pady=(0, 16))

        self.code_entry = ctk.CTkEntry(container, width=280, height=42, placeholder_text="123456",
                                        justify="center", font=ctk.CTkFont(size=20))
        self.code_entry.pack(padx=40)
        self.code_entry.bind("<Return>", lambda e: self._verify())

        self.error_label = ctk.CTkLabel(container, text="", text_color="#ff5555", font=ctk.CTkFont(size=12))
        self.error_label.pack(pady=(8, 0))

        btn_frame = ctk.CTkFrame(container, fg_color="transparent")
        btn_frame.pack(pady=(16, 30))
        ctk.CTkButton(btn_frame, text="Cancelar", fg_color="gray40", hover_color="gray30",
                      command=self.on_cancel).pack(side="left", padx=6)
        ctk.CTkButton(btn_frame, text="Verificar", command=self._verify).pack(side="left", padx=6)

        self.code_entry.focus()

    def _verify(self):
        code = self.code_entry.get()
        if totp.verify_code(self.vault_manager.totp_secret, code):
            self.audit.log("totp_success")
            self.on_verified()
        else:
            self.audit.log("totp_failed")
            self.error_label.configure(text="Código incorrecto o expirado.")
            self.code_entry.delete(0, "end")