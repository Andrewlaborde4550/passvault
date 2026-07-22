# PassVault 

Gestor de contraseñas de escritorio con cifrado de grado profesional, 100% local (sin nube, sin telemetría).

## Instalación

```bash
pip install -r requirements.txt
python main.py
```

## Correr la batería de pruebas de seguridad

```bash
python test_security_suite.py
```

Simula ataques reales contra el vault (robo de archivo, manipulación, fuerza bruta, etc.) y reporta PASS/FAIL por categoría — 34 pruebas en total.

## Empaquetar como `.exe` (Windows)

```bash
pip install pyinstaller
pyinstaller --onefile --windowed --name PassVault --icon=assets/icon.ico --add-data "assets;assets" --hidden-import=customtkinter --hidden-import=argon2 --hidden-import=cryptography main.py
```

`--icon` le pone el ícono al `.exe` en sí (barra de tareas, explorador de archivos). `--add-data "assets;assets"` es necesario aparte — sin eso, el `.exe` compila bien pero la ventana no encuentra el ícono en tiempo de ejecución (el código ya maneja esto sin romperse, solo se ve sin ícono).

Vas a ver una alerta de antivirus casi seguro — es un falso positivo típico del bootloader de PyInstaller `--onefile`, no significa que el `.exe` esté infectado. Para distribuirlo sin esa fricción, hay que firmarlo digitalmente (ver abajo).

### Firma de código (code signing)

Un `.exe` sin firmar es fácil de modificar y redistribuir sin que el usuario lo note, y dispara advertencias de Windows SmartScreen. Para firmarlo de verdad:

1. Conseguí un certificado de firma de código (Sectigo, DigiCert, etc. — para uso personal/pruebas también existen certificados self-signed, pero esos igual disparan SmartScreen la primera vez).
2. Editá `sign_build.bat` con la ruta a tu `.pfx` y su contraseña.
3. Corré `sign_build.bat` después de compilar con PyInstaller.

Esto no es algo que se pueda "programar" — depende de comprar/generar el certificado, así que quedó como script listo para cuando lo tengas.

## Arquitectura de seguridad

| Componente | Elección | Por qué |
|---|---|---|
| Derivación de clave | **Argon2id** (time_cost=4, memory_cost=256MB, parallelism=4) | Ganador del Password Hashing Competition. Resistente a ataques con GPU/ASIC, a diferencia de PBKDF2/SHA256. |
| Cifrado | **AES-256-GCM** | Cifrado autenticado: si alguien manipula un solo bit del archivo, el descifrado falla (auth tag). No solo protege confidencialidad, también integridad. |
| Salt | 16 bytes aleatorios, único por vault | Evita ataques de rainbow table / precomputación. |
| Nonce | 12 bytes aleatorios, único por cada escritura | Nunca se reutiliza un nonce con la misma clave (crítico en GCM). |
| Almacenamiento | Un solo archivo `vault.enc` cifrado, escritura atómica (tmp + rename + fsync) | Nunca queda un vault corrupto a medio escribir. |
| Comparación de claves | `hmac.compare_digest` (tiempo constante) | Evita ataques de timing. |
| **2FA (TOTP)** | Compatible con Google Authenticator/Authy | Segunda barrera si te roban la master password (keylogger, shoulder surfing). Opcional al crear el vault. |
| **Rate limiting** | Backoff exponencial tras 3 intentos fallidos (5s, 10s, 20s...) | Frena fuerza bruta interactiva contra la GUI. |
| **Backup automático** | Copia `.bak` de la versión anterior en cada guardado | Protege contra errores del usuario (ej. borrar algo sin querer) o corrupción. Restaurable desde el panel de Seguridad. |
| **Backup exportable** | Botón "Backup" — copia cifrada a donde elijas | Sigue requiriendo la master password para abrirse. |
| **Log de auditoría** | Registra desbloqueos, fallos, 2FA, backups, restauraciones | Visible desde el panel de Seguridad, con metadata únicamente (sin contraseñas). |
| **Auditoría de contraseñas** | Detecta contraseñas débiles y reutilizadas entre sitios | Corre en memoria sobre datos ya descifrados, no escribe nada a disco. |
| **Anti-debugging** | Detecta debuggers/herramientas de memory-dumping conocidas | Capa de fricción, no protección real — ver limitaciones abajo. |
| Clipboard | Auto-clear a los 20s | Reduce ventana de exposición si copias una password. |
| Sesión | Auto-lock a los 3 min de inactividad + borrado de clave de memoria (`zero_memory`) | Si dejas la app abierta y te alejas, se bloquea sola. |

## Lo que esto SÍ resiste

- **Robo del archivo `vault.enc`**: sin la master password, un atacante enfrenta Argon2id (256MB RAM + 4 iteraciones por intento) antes de siquiera poder probar una clave AES.
- **Manipulación del archivo**: cualquier bit alterado invalida el auth tag de GCM y el desbloqueo falla explícitamente.
- **Ataques de timing** en la verificación de clave.
- **Fuerza bruta offline**: cada intento cuesta ~1-2s y 256MB de RAM, lo que hace inviable probar millones de combinaciones rápido, incluso con GPUs.
- **Fuerza bruta interactiva** contra la GUI: el rate limiting lo frena después de 3 intentos.
- **Robo de la master password sin el segundo factor**: si activaste 2FA, no alcanza con la contraseña sola.
- **Pérdida/corrupción de la última versión guardada**: hay backup automático de un nivel.

## Limitaciones honestas (para que las tengas claras en el pentest)

- **No protege contra keyloggers o malware con acceso a la RAM del proceso** mientras el vault está desbloqueado — ningún gestor de contraseñas de software puro lo hace sin hardware dedicado (TPM/Secure Enclave).
- **Python no garantiza borrado real de memoria** (el GC puede dejar copias); mitigamos con `zero_memory()` pero no es tan fuerte como en C/Rust con `mlock`.
- **El anti-debugging es una capa de fricción, no una protección real** — un atacante con conocimiento medio puede saltárselo (parchear el binario, renombrar herramientas, debugging a nivel de hipervisor). Ver el docstring de `utils/anti_debug.py` para el detalle completo.
- **El archivo de lockout (`.lockout`) se puede borrar** por alguien con acceso al filesystem para resetear el contador de intentos — protege contra fuerza bruta *interactiva*, no contra alguien con control total del disco (ahí la protección real sigue siendo Argon2id).
- **El `.exe` sin firmar** dispara advertencias de antivirus/SmartScreen — necesita certificado de firma de código para distribución seria.
- **No hay sincronización entre dispositivos** — es 100% local por diseño (ver la conversación sobre por qué esto es más seguro, no menos).

## Estructura del proyecto

```
password_manager/
├── main.py                    # entry point, navegación entre pantallas
├── crypto_engine.py            # Argon2id + AES-256-GCM
├── vault_manager.py            # CRUD, lock/unlock, backups, persistencia
├── test_security_suite.py      # batería de pruebas de seguridad (34 tests)
├── sign_build.bat              # firma de código (requiere certificado propio)
├── gui/
│   ├── login_screen.py         # crear/desbloquear, rate limiting
│   ├── main_screen.py          # lista de entradas, chequeo anti-debug periódico
│   ├── entry_dialog.py         # crear/editar entrada + generador
│   ├── totp_screen.py          # setup y verificación de 2FA
│   ├── security_dialog.py      # salud de contraseñas + actividad + restaurar backup
│   ├── confirm_dialog.py       # diálogo de confirmación estilizado
│   └── info_dialog.py          # diálogo informativo estilizado
└── utils/
    ├── clipboard.py            # auto-clear
    ├── password_gen.py         # generador con `secrets`
    ├── security.py             # auto-lock por inactividad
    ├── totp.py                 # 2FA
    ├── lockout_manager.py      # rate limiting
    ├── audit.py                 # contraseñas débiles/reutilizadas
    ├── audit_log.py             # log de eventos de acceso
    ├── anti_debug.py            # detección de debuggers
    └── ui_helpers.py            # centrado de ventanas modales
```

## Categorías y organización

Las entradas se pueden agrupar por categoría (ej. "Trabajo", "Finanzas", "General" por defecto). El selector de categoría en el diálogo de nueva entrada sugiere las que ya existen, y normaliza mayúsculas/minúsculas para que "trabajo" y "Trabajo" no queden como categorías separadas. La lista principal se agrupa visualmente por categoría, y hay un filtro para ver solo una a la vez.

## Atajos de teclado

- `Ctrl+F` — foco en el buscador
- `Ctrl+N` — nueva entrada
- `Ctrl+L` — bloquear el vault
- `Esc` — cerrar cualquier ventana modal (nueva entrada, seguridad, confirmaciones, verificación 2FA)

## Pendientes opcionales 

- Exportación/importación en formato estándar (para migrar desde/hacia otros gestores)
- Sub-categorías o etiquetas múltiples por entrada (hoy es una categoría por entrada)