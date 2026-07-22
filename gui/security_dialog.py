"""
security_dialog.py
--------------------
Ventana modal con tres secciones:
1. Salud de contraseñas (débiles / reutilizadas)
2. Actividad reciente (desbloqueos, 2FA, backups)
3. Restaurar versión anterior del vault (si existe un .bak)
"""

import customtkinter as ctk
from datetime import datetime, timezone

from utils.audit import analyze_entries
from utils.audit_log import AuditLogger, EVENT_LABELS
from utils.ui_helpers import center_toplevel
from gui.confirm_dialog import ConfirmDialog


def _relative_time(iso_timestamp: str) -> str:
    try:
        ts = datetime.fromisoformat(iso_timestamp)
        delta = datetime.now(timezone.utc) - ts
        seconds = int(delta.total_seconds())
        if seconds < 60:
            return "hace un momento"
        if seconds < 3600:
            return f"hace {seconds // 60} min"
        if seconds < 86400:
            return f"hace {seconds // 3600} h"
        return f"hace {seconds // 86400} d"
    except ValueError:
        return iso_timestamp


class SecurityDialog(ctk.CTkToplevel):
    def __init__(self, master, vault_manager, on_restored):
        super().__init__(master)
        self.vault_manager = vault_manager
        self.on_restored = on_restored
        self.audit_log = AuditLogger(vault_manager.vault_path)

        self.title("Seguridad")
        self.resizable(False, False)
        center_toplevel(self, master, 480, 600)
        self.grab_set()

        self._build_ui()

    def _build_ui(self):
        scroll = ctk.CTkScrollableFrame(self, fg_color="transparent")
        scroll.pack(fill="both", expand=True, padx=20, pady=20)

        # ---- Salud de contraseñas ----
        ctk.CTkLabel(scroll, text="Salud de contraseñas", font=ctk.CTkFont(size=16, weight="bold")).pack(anchor="w", pady=(0, 8))

        report = analyze_entries(self.vault_manager.get_entries())

        if report["is_healthy"] and report["total_entries"] > 0:
            ctk.CTkLabel(scroll, text="✓ Todas tus contraseñas son fuertes y únicas.",
                         text_color="#55cc88").pack(anchor="w", pady=(0, 4))
        elif report["total_entries"] == 0:
            ctk.CTkLabel(scroll, text="No hay entradas todavía.", text_color="gray").pack(anchor="w", pady=(0, 4))
        else:
            if report["weak_entries"]:
                ctk.CTkLabel(scroll, text=f"⚠ {len(report['weak_entries'])} contraseña(s) débil(es):",
                             text_color="#ff8855").pack(anchor="w", pady=(4, 2))
                for e in report["weak_entries"]:
                    ctk.CTkLabel(scroll, text=f"   • {e['site']} — {e['strength']}",
                                 font=ctk.CTkFont(size=12), text_color="gray70").pack(anchor="w")

            if report["reused_groups"]:
                ctk.CTkLabel(scroll, text=f"⚠ {len(report['reused_groups'])} contraseña(s) reutilizada(s):",
                             text_color="#ff8855").pack(anchor="w", pady=(10, 2))
                for group in report["reused_groups"]:
                    sites = ", ".join(group["sites"])
                    ctk.CTkLabel(scroll, text=f"   • Usada en: {sites}",
                                 font=ctk.CTkFont(size=12), text_color="gray70", wraplength=400, justify="left").pack(anchor="w")

        # ---- Versión anterior ----
        if self.vault_manager.has_previous_version():
            ctk.CTkFrame(scroll, height=1, fg_color="gray30").pack(fill="x", pady=16)
            ctk.CTkLabel(scroll, text="Versión anterior disponible", font=ctk.CTkFont(size=16, weight="bold")).pack(anchor="w", pady=(0, 6))
            ctk.CTkLabel(scroll, text="Hay un respaldo automático de la versión anterior a tu último cambio.",
                         font=ctk.CTkFont(size=12), text_color="gray70", wraplength=420, justify="left").pack(anchor="w", pady=(0, 8))
            ctk.CTkButton(scroll, text="Restaurar versión anterior", fg_color="#a86a32", hover_color="#7a4c24",
                          command=self._confirm_restore).pack(anchor="w")

        # ---- Actividad reciente ----
        ctk.CTkFrame(scroll, height=1, fg_color="gray30").pack(fill="x", pady=16)
        ctk.CTkLabel(scroll, text="Actividad reciente", font=ctk.CTkFont(size=16, weight="bold")).pack(anchor="w", pady=(0, 8))

        events = self.audit_log.get_events(15)
        if not events:
            ctk.CTkLabel(scroll, text="Sin actividad registrada.", text_color="gray").pack(anchor="w")
        for ev in events:
            label = EVENT_LABELS.get(ev["event"], ev["event"])
            row = ctk.CTkFrame(scroll, fg_color="transparent")
            row.pack(fill="x", pady=2)
            ctk.CTkLabel(row, text=label, font=ctk.CTkFont(size=12), anchor="w").pack(side="left")
            ctk.CTkLabel(row, text=_relative_time(ev["timestamp"]), font=ctk.CTkFont(size=11),
                         text_color="gray60", anchor="e").pack(side="right")

        ctk.CTkButton(self, text="Cerrar", fg_color="gray40", hover_color="gray30",
                      command=self.destroy).pack(pady=(0, 16))

    def _confirm_restore(self):
        confirmed = ConfirmDialog.ask(
            self,
            title="Restaurar versión anterior",
            message="Esto reemplaza el vault actual con el respaldo automático de antes de tu "
                    "último cambio. Vas a tener que volver a desbloquear.",
            confirm_text="Restaurar",
            cancel_text="Cancelar",
        )
        if not confirmed:
            return
        self.vault_manager.restore_previous_version()
        self.audit_log.log("previous_version_restored")
        self.destroy()
        self.on_restored()