"""
confirm_dialog.py
-------------------
Diálogo de confirmación (Sí/No) estilizado con CustomTkinter, para no
depender del messagebox nativo de Windows/Tk (que rompe con el tema
oscuro y se ve fuera de lugar).

Uso:
    if ConfirmDialog.ask(self, "Título", "Mensaje...", confirm_text="Guardar igual"):
        ...
"""

import customtkinter as ctk
from utils.ui_helpers import center_toplevel

DIALOG_WIDTH = 420


class ConfirmDialog(ctk.CTkToplevel):
    def __init__(self, master, title, message, confirm_text="Sí", cancel_text="Cancelar",
                 confirm_color="#a86a32", confirm_hover="#7a4c24", icon="⚠"):
        super().__init__(master)
        self.result = False

        self.title(title)
        self.resizable(False, False)
        self.grab_set()

        self._build_ui(title, message, confirm_text, cancel_text, confirm_color, confirm_hover, icon)

        # Alto dinámico según cuántas líneas tenga el mensaje, para que no quede
        # ni apretado ni con espacio de sobra.
        line_count = message.count("\n") + 1
        height = 150 + line_count * 20
        center_toplevel(self, master, DIALOG_WIDTH, height)

    def _build_ui(self, title, message, confirm_text, cancel_text, confirm_color, confirm_hover, icon):
        body = ctk.CTkFrame(self, fg_color="transparent")
        body.pack(fill="both", expand=True, padx=24, pady=(24, 16))

        header = ctk.CTkFrame(body, fg_color="transparent")
        header.pack(fill="x", pady=(0, 12))

        icon_badge = ctk.CTkLabel(header, text=icon, font=ctk.CTkFont(size=20),
                                   fg_color="#3a2a1a", text_color="#ff8855",
                                   width=40, height=40, corner_radius=20)
        icon_badge.pack(side="left")

        ctk.CTkLabel(header, text=title, font=ctk.CTkFont(size=16, weight="bold"),
                     anchor="w").pack(side="left", padx=(12, 0))

        ctk.CTkLabel(body, text=message, font=ctk.CTkFont(size=13), text_color="gray80",
                     justify="left", anchor="w", wraplength=DIALOG_WIDTH - 48).pack(fill="x", pady=(0, 20))

        btn_frame = ctk.CTkFrame(body, fg_color="transparent")
        btn_frame.pack(fill="x")
        btn_frame.grid_columnconfigure((0, 1), weight=1, uniform="confirm_btns")

        ctk.CTkButton(btn_frame, text=cancel_text, fg_color="gray35", hover_color="gray25",
                      command=self._cancel).grid(row=0, column=0, sticky="ew", padx=(0, 6))
        ctk.CTkButton(btn_frame, text=confirm_text, fg_color=confirm_color, hover_color=confirm_hover,
                      command=self._confirm).grid(row=0, column=1, sticky="ew", padx=(6, 0))

    def _confirm(self):
        self.result = True
        self.destroy()

    def _cancel(self):
        self.result = False
        self.destroy()

    @staticmethod
    def ask(master, title, message, confirm_text="Sí", cancel_text="Cancelar",
            confirm_color="#a86a32", confirm_hover="#7a4c24", icon="⚠") -> bool:
        dialog = ConfirmDialog(master, title, message, confirm_text, cancel_text,
                                confirm_color, confirm_hover, icon)
        master.wait_window(dialog)
        return dialog.result