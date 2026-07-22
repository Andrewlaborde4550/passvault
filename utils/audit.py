"""
audit.py
--------
Analiza las entradas del vault en memoria para detectar:
- Contraseñas débiles (según utils.password_gen.estimate_strength)
- Contraseñas reutilizadas en más de un sitio

Nota: este análisis corre completamente en memoria sobre datos ya
descifrados (el vault tiene que estar desbloqueado), y no escribe
ni loguea ninguna contraseña en texto plano a disco.
"""

from collections import defaultdict
from utils.password_gen import estimate_strength

WEAK_LABELS = {"Muy débil", "Débil"}


def analyze_entries(entries: list) -> dict:
    weak_entries = []
    password_to_sites = defaultdict(list)

    for entry in entries:
        pwd = entry.get("password", "")
        site = entry.get("site", "(sin nombre)")

        strength = estimate_strength(pwd) if pwd else "Muy débil"
        if strength in WEAK_LABELS:
            weak_entries.append({"site": site, "strength": strength})

        password_to_sites[pwd].append(site)

    reused_groups = [
        {"sites": sites, "count": len(sites)}
        for pwd, sites in password_to_sites.items()
        if len(sites) > 1
    ]

    return {
        "total_entries": len(entries),
        "weak_entries": weak_entries,
        "reused_groups": reused_groups,
        "is_healthy": len(weak_entries) == 0 and len(reused_groups) == 0,
    }