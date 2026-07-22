@"
@echo off
REM sign_build.bat
REM ----------------
REM Script para firmar PassVault.exe una vez que tengas un certificado
REM de firma de codigo (.pfx). No hace nada util sin ese certificado.
REM
REM USO:
REM   1. Compila primero: pyinstaller --onefile --windowed --name PassVault main.py
REM   2. Edita las 3 variables de abajo con tus datos reales
REM   3. Corre: sign_build.bat

set CERT_PATH=ruta\a\tu\certificado.pfx
set CERT_PASSWORD=tu_password_del_certificado
set TIMESTAMP_SERVER=http://timestamp.digicert.com

signtool sign /f "%CERT_PATH%" /p "%CERT_PASSWORD%" /t "%TIMESTAMP_SERVER%" /d "PassVault" dist\PassVault.exe

REM Verificar que la firma quedo bien:
signtool verify /pa dist\PassVault.exe

pause
"@ | Out-File -FilePath sign_build.bat -Encoding ascii