"""
anti_debug.py
--------------
Detección básica de debuggers y herramientas de memory-dumping adjuntas
al proceso. Dos capas:

1. IsDebuggerPresent (API nativa de Windows) — detecta si un debugger
   está attacheado directamente al proceso de PassVault.
2. Escaneo de procesos corriendo por nombre — detecta herramientas
   conocidas de reversing/debugging/memory-dumping activas en el sistema
   (no necesariamente attacheadas a PassVault, pero es una señal de alerta).

LIMITACIÓN HONESTA (léela antes de confiar en esto para algo serio):
Esto es una capa de fricción, NO una protección real. Un atacante con
conocimiento medio puede:
- Parchear el binario para saltarse la llamada a IsDebuggerPresent.
- Renombrar el ejecutable del debugger para no matchear la lista.
- Usar técnicas de debugging que no dejan las señales que buscamos acá
  (ej. debugging a nivel de hipervisor/VM).
Como PassVault es Python (interpretado, o empaquetado con PyInstaller,
que es trivialmente reversible con herramientas como pyinstxtractor),
ningún anti-debugging por software va a detener a alguien decidido con
las herramientas correctas. Esto sube el costo de un ataque casual, no
lo hace imposible. La protección real sigue siendo Argon2id + AES-256-GCM
sobre los datos en reposo — eso sí es matemáticamente sólido.
"""

import sys
import ctypes

SUSPICIOUS_PROCESS_NAMES = {
    # Debuggers
    "x64dbg.exe", "x32dbg.exe", "x96dbg.exe", "ollydbg.exe", "windbg.exe",
    "immunitydebugger.exe", "immunity debugger.exe",
    # Disassemblers / decompiladores
    "ida.exe", "ida64.exe", "idaq.exe", "idaq64.exe", "ghidra.exe", "ghidrarun.exe",
    "dnspy.exe", "cutter.exe", "radare2.exe", "r2.exe",
    # Memory dumping / patching
    "procdump.exe", "procdump64.exe", "cheatengine-x86_64.exe", "cheatengine-i386.exe",
    "scylla.exe", "scylla_x64.exe", "scylla_x86.exe", "pe-bear.exe",
    # Inyección de procesos / hooking
    "frida-server.exe", "frida.exe", "injector.exe",
    # Análisis de sistema con capacidad de leer memoria de otros procesos
    "processhacker.exe", "procmon.exe", "procmon64.exe", "apimonitor.exe", "api monitor.exe",
}


def is_debugger_present() -> bool:
    """Chequea vía la API nativa de Windows si hay un debugger attacheado a este proceso."""
    if sys.platform != "win32":
        return False
    try:
        return bool(ctypes.windll.kernel32.IsDebuggerPresent())
    except Exception:
        return False


def scan_suspicious_processes() -> list:
    """
    Devuelve los nombres de procesos sospechosos (debuggers/herramientas
    de memory-dumping) que estén corriendo en el sistema en este momento.
    Si psutil no está disponible o falla, retorna lista vacía en vez de
    romper la app (esto es una capa extra, no algo crítico).
    """
    try:
        import psutil
    except ImportError:
        return []

    found = []
    try:
        for proc in psutil.process_iter(["name"]):
            name = (proc.info.get("name") or "").lower()
            if name in SUSPICIOUS_PROCESS_NAMES:
                found.append(name)
    except Exception:
        pass
    return found


def check_parent_process() -> str:
    """
    Algunos debuggers lanzan el programa objetivo como proceso hijo directo.
    Si el proceso padre de PassVault es una herramienta sospechosa, es una
    señal más fuerte que solo verla corriendo en paralelo en el sistema.
    """
    try:
        import psutil
        parent = psutil.Process().parent()
        if parent is None:
            return ""
        name = (parent.name() or "").lower()
        return name if name in SUSPICIOUS_PROCESS_NAMES else ""
    except Exception:
        return ""


# Umbral para detectar "single-stepping": recorrer código línea por línea con
# un debugger detiene la ejecución en cada instrucción, así que una operación
# que normalmente tarda 1-2s (la derivación Argon2id) puede tardar minutos si
# alguien está single-stepping a través de ella. El umbral es generoso a
# propósito para no generar falsos positivos en hardware lento.
DERIVATION_TIME_ANOMALY_THRESHOLD_SECONDS = 8.0


def check(derivation_seconds: float = None) -> dict:
    """
    Chequeo combinado. `derivation_seconds`, si se pasa, es cuánto tardó la
    última derivación Argon2id — se usa para detectar single-stepping.
    Retorna {'suspicious': bool, 'reasons': [...]}.
    """
    reasons = []
    if is_debugger_present():
        reasons.append("Debugger attacheado al proceso")

    procs = scan_suspicious_processes()
    if procs:
        reasons.append(f"Procesos sospechosos activos: {', '.join(set(procs))}")

    parent = check_parent_process()
    if parent:
        reasons.append(f"El proceso padre es una herramienta sospechosa: {parent}")

    if derivation_seconds is not None and derivation_seconds > DERIVATION_TIME_ANOMALY_THRESHOLD_SECONDS:
        reasons.append(
            f"La derivación de la clave tardó {derivation_seconds:.1f}s (anómalo) — "
            "posible ejecución paso a paso con un debugger"
        )

    return {"suspicious": len(reasons) > 0, "reasons": reasons}
