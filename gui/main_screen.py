"""
main_screen.py
---------------
Pantalla principal tras desbloquear el vault: lista de entradas con
búsqueda, botones de copiar usuario/password, editar, eliminar, y
botón de bloqueo manual.
"""

import customtkinter as ctk
from tkinter import filedialog
from datetime import datetime
from gui.entry_dialog import EntryDialog
from gui.security_dialog import SecurityDialog
from gui.info_dialog import InfoDialog
from utils.clipboard import SecureClipboard
from utils.ui_helpers import center_toplevel
from utils.audit_log import AuditLogger
from utils import anti_debug

import random

DEBUG_CHECK_INTERVAL_MS = 10000  # 10 segundos base
DEBUG_CHECK_JITTER_MS = 3000     # +/- variación, para no ser 100% predecible


class MainScreen(ctk.CTkFrame):
    def __init__(self, master, vault_manager, on_lock):
        super().__init__(master, fg_color="transparent")
        self.vault_manager = vault_manager
        self.on_lock = on_lock
        self.clipboard = SecureClipboard(clear_after_seconds=20)
        self.audit_log = AuditLogger(vault_manager.vault_path)

        self._build_ui()
        self._refresh_list()
        self._schedule_debug_check()
        self._bind_shortcuts()

    def _bind_shortcuts(self):
        # Atado a la ventana raíz (no bind_all) porque si usáramos bind_all el atajo
        # quedaría pegado globalmente incluso después de bloquear el vault. El cleanup
        # se hace explícitamente vía cleanup_shortcuts(), llamado desde main.py antes
        # de destruir la pantalla — depender del evento <Destroy> para esto no resultó
        # confiable (el orden de propagación del evento no garantiza que dispare a tiempo).
        root = self.winfo_toplevel()
        self._shortcut_root = root
        root.bind("<Control-f>", lambda e: self._focus_search())
        root.bind("<Control-F>", lambda e: self._focus_search())
        root.bind("<Control-n>", lambda e: self._add_entry())
        root.bind("<Control-N>", lambda e: self._add_entry())
        root.bind("<Control-l>", lambda e: self.on_lock())
        root.bind("<Control-L>", lambda e: self.on_lock())

    def cleanup_shortcuts(self):
        """Debe llamarse ANTES de destruir esta pantalla (ver main.py: _clear_screen)."""
        for seq in ("<Control-f>", "<Control-F>", "<Control-n>", "<Control-N>", "<Control-l>", "<Control-L>"):
            try:
                self._shortcut_root.unbind(seq)
            except Exception:
                pass

    def _focus_search(self):
        self.search_entry.focus()
        self.search_entry.select_range(0, "end")

    CONTENT_WIDTH = 640

    def _build_ui(self):
        # Columnas laterales elásticas + columna central de ancho fijo = contenido siempre centrado
        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(0, weight=1)
        self.grid_columnconfigure(1, weight=0)
        self.grid_columnconfigure(2, weight=1)

        content = ctk.CTkFrame(self, fg_color="transparent", width=self.CONTENT_WIDTH)
        content.grid(row=0, column=1, sticky="ns", pady=20)
        content.grid_propagate(False)
        content.pack_propagate(False)

        top_bar = ctk.CTkFrame(content, fg_color="transparent")
        top_bar.pack(fill="x", pady=(0, 10))

        ctk.CTkLabel(top_bar, text="🔒 PassVault", font=ctk.CTkFont(size=20, weight="bold")).pack(side="left")
        ctk.CTkButton(top_bar, text="Bloquear", fg_color="gray40", width=90, command=self.on_lock).pack(side="right")

        actions_bar = ctk.CTkFrame(content, fg_color="transparent")
        actions_bar.pack(fill="x", pady=(0, 14))

        ctk.CTkButton(actions_bar, text="+ Nueva entrada", width=150, command=self._add_entry).pack(side="left")
        ctk.CTkButton(actions_bar, text="Backup", fg_color="gray30", hover_color="gray20", width=90,
                      command=self._export_backup).pack(side="left", padx=(8, 0))
        ctk.CTkButton(actions_bar, text="Seguridad", fg_color="gray30", hover_color="gray20", width=90,
                      command=self._open_security).pack(side="left", padx=(8, 0))

        search_frame = ctk.CTkFrame(content, fg_color="transparent")
        search_frame.pack(fill="x", pady=(0, 14))
        search_frame.grid_columnconfigure(0, weight=1)

        self.search_entry = ctk.CTkEntry(search_frame, placeholder_text="Buscar sitio o usuario...", height=36)
        self.search_entry.grid(row=0, column=0, sticky="ew")
        self.search_entry.bind("<KeyRelease>", lambda e: self._refresh_list())

        self.category_filter = ctk.CTkComboBox(search_frame, height=36, width=160,
                                                 values=["Todas"], command=lambda v: self._refresh_list(),
                                                 state="readonly")
        self.category_filter.grid(row=0, column=1, padx=(8, 0))
        self.category_filter.set("Todas")
        self._refresh_categories()

        self.list_container = ctk.CTkScrollableFrame(content, fg_color="transparent", width=self.CONTENT_WIDTH - 20)
        self.list_container.pack(fill="both", expand=True)

    def _refresh_categories(self):
        cats = self.vault_manager.get_categories()
        values = ["Todas"] + cats
        current = self.category_filter.get()
        self.category_filter.configure(values=values)
        if current not in values:
            self.category_filter.set("Todas")

    def _refresh_list(self):
        for widget in self.list_container.winfo_children():
            widget.destroy()

        search = self.search_entry.get()
        selected_category = self.category_filter.get()
        category_filter = "" if selected_category == "Todas" else selected_category
        entries = self.vault_manager.get_entries(search, category_filter)

        if not entries:
            ctk.CTkLabel(self.list_container, text="No hay entradas todavía.", text_color="gray").pack(pady=40)
            return

        # Agrupar por categoría (alfabético), y dentro de cada grupo por sitio
        grouped = {}
        for entry in entries:
            cat = entry.get("category", self.vault_manager.DEFAULT_CATEGORY)
            grouped.setdefault(cat, []).append(entry)

        for cat in sorted(grouped.keys()):
            header = ctk.CTkLabel(self.list_container, text=cat.upper(), font=ctk.CTkFont(size=11, weight="bold"),
                                   text_color="gray50", anchor="w")
            header.pack(fill="x", pady=(12, 2), padx=2)
            for entry in sorted(grouped[cat], key=lambda e: e["site"].lower()):
                self._render_entry_row(entry)

    def _render_entry_row(self, entry):
        row = ctk.CTkFrame(self.list_container, corner_radius=10)
        row.pack(fill="x", pady=6)

        # Fila superior: sitio + usuario
        info_frame = ctk.CTkFrame(row, fg_color="transparent")
        info_frame.pack(fill="x", padx=16, pady=(12, 8))

        site_label = ctk.CTkLabel(info_frame, text=entry["site"], font=ctk.CTkFont(size=15, weight="bold"), anchor="w")
        site_label.pack(fill="x")
        user_label = ctk.CTkLabel(info_frame, text=entry["username"], font=ctk.CTkFont(size=12),
                                   text_color="gray70", anchor="w")
        user_label.pack(fill="x")

        # Fila inferior: acciones, distribuidas parejo en todo el ancho
        btn_frame = ctk.CTkFrame(row, fg_color="transparent")
        btn_frame.pack(fill="x", padx=16, pady=(0, 12))
        for i in range(4):
            btn_frame.grid_columnconfigure(i, weight=1, uniform="actions")

        ctk.CTkButton(btn_frame, text="Usuario", height=30,
                      command=lambda: self.clipboard.copy(entry["username"])).grid(row=0, column=0, sticky="ew", padx=(0, 4))
        ctk.CTkButton(btn_frame, text="Password", height=30,
                      command=lambda: self.clipboard.copy(entry["password"])).grid(row=0, column=1, sticky="ew", padx=4)
        ctk.CTkButton(btn_frame, text="Editar", height=30, fg_color="gray35", hover_color="gray25",
                      command=lambda: self._edit_entry(entry)).grid(row=0, column=2, sticky="ew", padx=4)
        ctk.CTkButton(btn_frame, text="Eliminar", height=30, fg_color="#a83232", hover_color="#7a2424",
                      command=lambda: self._delete_entry(entry)).grid(row=0, column=3, sticky="ew", padx=(4, 0))

    def _schedule_debug_check(self):
        interval = DEBUG_CHECK_INTERVAL_MS + random.randint(-DEBUG_CHECK_JITTER_MS, DEBUG_CHECK_JITTER_MS)
        self.after(max(interval, 3000), self._check_for_debugger)

    def _check_for_debugger(self):
        if not self.winfo_exists():
            return  # la pantalla ya cambió (ej. se bloqueó por otra vía)

        result = anti_debug.check()
        if result["suspicious"]:
            self.audit_log.log("debugger_detected", detail="; ".join(result["reasons"]))
            self.on_lock()  # bloqueo inmediato, sin preguntar — ya no hay diálogo de "continuar igual" en sesión activa
            return

        self._schedule_debug_check()

    def _export_backup(self):
        default_name = f"passvault_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.enc"
        destination = filedialog.asksaveasfilename(
            defaultextension=".enc",
            initialfile=default_name,
            filetypes=[("Vault cifrado", "*.enc"), ("Todos los archivos", "*.*")],
            title="Guardar backup del vault",
        )
        if not destination:
            return
        try:
            self.vault_manager.export_backup(destination)
            self.audit_log.log("backup_exported")
            InfoDialog.show(
                self, "Backup creado",
                "Backup guardado correctamente.\n\n"
                "Sigue cifrado con tu master password — vas a necesitarla "
                "para poder abrirlo si algún día lo restaurás.",
                kind="success",
            )
        except Exception as e:
            InfoDialog.show(self, "Error al crear backup", str(e), kind="error")

    def _open_security(self):
        SecurityDialog(self, self.vault_manager, on_restored=self.on_lock)

    def _add_entry(self):
        EntryDialog(self, self.vault_manager, on_save=self._save_entry)

    def _edit_entry(self, entry):
        EntryDialog(self, self.vault_manager, on_save=self._save_entry, entry=entry)

    def _save_entry(self, site, username, password, notes, category, existing_entry):
        if existing_entry:
            self.vault_manager.update_entry(
                existing_entry["id"], site=site, username=username, password=password,
                notes=notes, category=category
            )
        else:
            self.vault_manager.add_entry(site, username, password, notes, category)
        self._refresh_categories()
        self._refresh_list()

    def _delete_entry(self, entry):
        confirm = ctk.CTkToplevel(self)
        confirm.title("Confirmar")
        confirm.resizable(False, False)
        center_toplevel(confirm, self, 300, 150)
        confirm.grab_set()
        confirm.bind("<Escape>", lambda e: confirm.destroy())

        ctk.CTkLabel(confirm, text=f"¿Eliminar '{entry['site']}'?", wraplength=260).pack(pady=20)

        def do_delete():
            self.vault_manager.delete_entry(entry["id"])
            confirm.destroy()
            self._refresh_categories()
            self._refresh_list()

        btn_frame = ctk.CTkFrame(confirm, fg_color="transparent")
        btn_frame.pack(pady=10)
        ctk.CTkButton(btn_frame, text="Cancelar", fg_color="gray40", command=confirm.destroy).pack(side="left", padx=8)
        ctk.CTkButton(btn_frame, text="Eliminar", fg_color="#a83232", hover_color="#7a2424", command=do_delete).pack(side="left", padx=8)