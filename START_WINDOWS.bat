@echo off
setlocal
pushd "%~dp0"
where py >nul 2>nul
if errorlevel 1 goto use_python
py -3 scanner_gui.py
goto finished
:use_python
python scanner_gui.py
:finished
if errorlevel 1 pause
popd
endlocal
