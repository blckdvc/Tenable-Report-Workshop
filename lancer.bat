@echo off
chcp 65001 >nul
cd /d "%~dp0"
where py >nul 2>nul && (set PY=py -3) || (set PY=python)
if not exist ".venv\Scripts\python.exe" (
  echo Premiere installation : creation de l'environnement Python...
  %PY% -m venv .venv || (echo Python 3.9 ou plus recent est requis : https://www.python.org/downloads/ & pause & exit /b 1)
  ".venv\Scripts\python.exe" -m pip install --quiet --upgrade pip
  ".venv\Scripts\python.exe" -m pip install --quiet -r requirements.txt || (echo Installation des bibliotheques impossible. & pause & exit /b 1)
)
for /f "skip=1 tokens=*" %%h in ('certutil -hashfile requirements.txt MD5') do if not defined REQH set REQH=%%h
set OLDH=
if exist ".venv\.requirements.stamp" set /p OLDH=<".venv\.requirements.stamp"
if not "%REQH%"=="%OLDH%" (
  echo Mise a jour des bibliotheques...
  ".venv\Scripts\python.exe" -m pip install --quiet -r requirements.txt || (echo Installation des bibliotheques impossible. & pause & exit /b 1)
)
>".venv\.requirements.stamp" echo %REQH%

".venv\Scripts\python.exe" app.py
pause
