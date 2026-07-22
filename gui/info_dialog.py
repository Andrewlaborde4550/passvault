"""
info_dialog.py
----------------
Diálogo informativo de un solo botón (info / éxito / error), estilizado
con CustomTkinter en vez del messagebox nativo de Windows.

Uso:
    InfoDialog.show(self, "Backup creado", "Guardado correctamente.", kind="success")
    InfoDialog.show(self, "Error", "Algo salió mal.", kind="error")
"""

import customtkinter as ctk
from utils.ui_helpers import center_toplevel

DIALOG_WIDTH = 400

KIND_STYLES = {
    "info": {"icon": "ℹ", "bg": "#1a2a3a", "fg": "#5aa9e6", "btn_color": "#2f6fa8", "btn_hover": "#255a87"},
    "success": {"icon": "✓", "bg": "#1a3a2a", "fg": "#55cc88", "btn_color": "#2f8a55", "btn_hover": "#256e44"},
    "error": {"icon": "✕", "bg": "#3a1a1a", "fg": "#ff6b6b", "btn_color": "#a83232", "btn_hover": "#7a2424"},
}


class InfoDialog(ctk.CTkToplevel):
    def __init__(self, master, title, message, kind="info", button_text="Aceptar"):
        super().__init__(master)
        style = KIND_STYLES.get(kind, KIND_STYLES["info"])

        self.title(title)
        self.resizable(False, False)
        self.grab_set()

        self._build_ui(title, message, style, button_text)

        line_count = message.count("\n") + 1
        height = 140 + line_count * 20
        center_toplevel(self, master, DIALOG_WIDTH, height)

    def _build_ui(self, title, message, style, button_text):
        body = ctk.CTkFrame(self, fg_color="transparent")
        body.pack(fill="both", expand=True, padx=24, pady=(24, 16))

        header = ctk.CTkFrame(body, fg_color="transparent")
        header.pack(fill="x", pady=(0, 12))

        icon_badge = ctk.CTkLabel(header, text=style["icon"], font=ctk.CTkFont(size=20, weight="bold"),
                                   fg_color=style["bg"], text_color=style["fg"],
                                   width=40, height=40, corner_radius=20)
        icon_badge.pack(side="left")

        ctk.CTkLabel(header, text=title, font=ctk.CTkFont(size=16, weight="bold"),
                     anchor="w").pack(side="left", padx=(12, 0))

        ctk.CTkLabel(body, text=message, font=ctk.CTkFont(size=13), text_color="gray80",
                     justify="left", anchor="w", wraplength=DIALOG_WIDTH - 48).pack(fill="x", pady=(0, 20))

        ctk.CTkButton(body, text=button_text, fg_color=style["btn_color"], hover_color=style["btn_hover"],
                      command=self.destroy).pack(fill="x")

    @staticmethod
    def show(master, title, message, kind="info", button_text="Aceptar"):
        InfoDialog(master, title, message, kind, button_text)