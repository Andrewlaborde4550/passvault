"""
entry_dialog.py
----------------
Ventana modal para agregar/editar una entrada (sitio, usuario, password, notas),
con generador de contraseña integrado.
"""

import customtkinter as ctk
from utils.password_gen import generate_password, estimate_strength
from utils.ui_helpers import center_toplevel
from gui.confirm_dialog import ConfirmDialog

DIALOG_WIDTH = 420
DIALOG_HEIGHT = 560
WEAK_LABELS = {"Muy débil", "Débil"}


class EntryDialog(ctk.CTkToplevel):
    def __init__(self, master, vault_manager, on_save, entry=None):
        super().__init__(master)
        self.vault_manager = vault_manager
        self.on_save = on_save
        self.entry = entry  # None = nueva entrada, dict = editar existente

        self.title("Editar entrada" if entry else "Nueva entrada")
        self.resizable(False, False)
        center_toplevel(self, master, DIALOG_WIDTH, DIALOG_HEIGHT)
        self.grab_set()  # modal
        self.bind("<Escape>", lambda e: self.destroy())

        self._build_ui()

    def _build_ui(self):
        # Contenedor con margen interno uniforme, para que todo quede
        # alineado al mismo ancho en vez de pegado a los bordes de la ventana.
        body = ctk.CTkFrame(self, fg_color="transparent")
        body.pack(fill="both", expand=True, padx=20, pady=20)

        ctk.CTkLabel(body, text="Sitio / Aplicación", anchor="w").pack(fill="x")
        self.site_entry = ctk.CTkEntry(body, height=36)
        self.site_entry.pack(fill="x", pady=(4, 14))

        ctk.CTkLabel(body, text="Usuario / Email", anchor="w").pack(fill="x")
        self.username_entry = ctk.CTkEntry(body, height=36)
        self.username_entry.pack(fill="x", pady=(4, 14))

        ctk.CTkLabel(body, text="Contraseña", anchor="w").pack(fill="x")
        pwd_frame = ctk.CTkFrame(body, fg_color="transparent")
        pwd_frame.pack(fill="x", pady=(4, 0))
        pwd_frame.grid_columnconfigure(0, weight=1)

        self.password_entry = ctk.CTkEntry(pwd_frame, height=36, show="•")
        self.password_entry.grid(row=0, column=0, sticky="ew")
        self.password_entry.bind("<KeyRelease>", self._update_feedback)

        self._show_password = False
        self.show_btn = ctk.CTkButton(pwd_frame, text="Mostrar", width=76, height=36, command=self._toggle_show)
        self.show_btn.grid(row=0, column=1, padx=(6, 0))

        gen_btn = ctk.CTkButton(pwd_frame, text="Generar", width=76, height=36, command=self._generate)
        gen_btn.grid(row=0, column=2, padx=(6, 0))

        self.strength_label = ctk.CTkLabel(body, text="", font=ctk.CTkFont(size=11), anchor="w", justify="left")
        self.strength_label.pack(fill="x", pady=(4, 0))

        self.reuse_label = ctk.CTkLabel(body, text="", font=ctk.CTkFont(size=11), anchor="w",
                                         text_color="#ff8855", justify="left", wraplength=360)
        self.reuse_label.pack(fill="x", pady=(2, 14))

        ctk.CTkLabel(body, text="Notas (opcional)", anchor="w").pack(fill="x")
        self.notes_entry = ctk.CTkTextbox(body, height=70)
        self.notes_entry.pack(fill="x", pady=(4, 14))

        ctk.CTkLabel(body, text="Categoría", anchor="w").pack(fill="x")
        existing_categories = self.vault_manager.get_categories()
        if self.vault_manager.DEFAULT_CATEGORY not in existing_categories:
            existing_categories = [self.vault_manager.DEFAULT_CATEGORY] + existing_categories
        self.category_combo = ctk.CTkComboBox(body, height=36, values=existing_categories)
        self.category_combo.pack(fill="x", pady=(4, 0))
        self.category_combo.set(self.vault_manager.DEFAULT_CATEGORY)

        btn_frame = ctk.CTkFrame(body, fg_color="transparent")
        btn_frame.pack(fill="x", pady=(20, 0))
        btn_frame.grid_columnconfigure((0, 1), weight=1, uniform="dialog_btns")
        ctk.CTkButton(btn_frame, text="Cancelar", fg_color="gray40", hover_color="gray30",
                      command=self.destroy).grid(row=0, column=0, sticky="ew", padx=(0, 6))
        ctk.CTkButton(btn_frame, text="Guardar", command=self._save).grid(row=0, column=1, sticky="ew", padx=(6, 0))

        if self.entry:
            self.site_entry.insert(0, self.entry.get("site", ""))
            self.username_entry.insert(0, self.entry.get("username", ""))
            self.password_entry.insert(0, self.entry.get("password", ""))
            self.notes_entry.insert("1.0", self.entry.get("notes", ""))
            self.category_combo.set(self.entry.get("category", self.vault_manager.DEFAULT_CATEGORY))
            self._update_feedback()

        self.site_entry.focus()

    def _toggle_show(self):
        self._show_password = not self._show_password
        self.password_entry.configure(show="" if self._show_password else "•")
        self.show_btn.configure(text="Ocultar" if self._show_password else "Mostrar")

    def _generate(self):
        pwd = generate_password(length=20)
        self.password_entry.delete(0, "end")
        self.password_entry.insert(0, pwd)
        self._update_feedback()

    def _update_feedback(self, event=None):
        pwd = self.password_entry.get()
        if not pwd:
            self.strength_label.configure(text="")
            self.reuse_label.configure(text="")
            return

        strength = estimate_strength(pwd)
        if strength in WEAK_LABELS:
            self.strength_label.configure(text=f"⚠ Fortaleza: {strength}", text_color="#ff8855")
        else:
            self.strength_label.configure(text=f"Fortaleza: {strength}", text_color="gray70")

        # Reutilización: comparar contra las demás entradas del vault (excluyéndose a sí misma si se está editando)
        other_sites = [
            e["site"] for e in self.vault_manager.get_entries()
            if e["password"] == pwd and (self.entry is None or e["id"] != self.entry["id"])
        ]
        if other_sites:
            sites_str = ", ".join(other_sites)
            self.reuse_label.configure(text=f"⚠ Esta contraseña ya se usa en: {sites_str}")
        else:
            self.reuse_label.configure(text="")

    def _has_weak_or_reused_warning(self) -> bool:
        return bool(self.strength_label.cget("text")) and "⚠" in self.strength_label.cget("text") \
            or bool(self.reuse_label.cget("text"))

    def _save(self):
        site = self.site_entry.get().strip()
        username = self.username_entry.get().strip()
        password = self.password_entry.get()
        notes = self.notes_entry.get("1.0", "end").strip()
        category = self.category_combo.get().strip() or self.vault_manager.DEFAULT_CATEGORY

        if not site or not password:
            return  # validación mínima; podría mostrarse un error inline

        if self._has_weak_or_reused_warning():
            warnings = []
            if "⚠" in self.strength_label.cget("text"):
                warnings.append("• La contraseña es débil.")
            if self.reuse_label.cget("text"):
                warnings.append("• " + self.reuse_label.cget("text").replace("⚠ ", ""))
            proceed = ConfirmDialog.ask(
                self,
                title="Contraseña insegura",
                message="Detectamos lo siguiente:\n\n" + "\n".join(warnings),
                confirm_text="Guardar igual",
                cancel_text="Cancelar",
            )
            if not proceed:
                return

        self.on_save(site, username, password, notes, category, self.entry)
        self.destroy()