@echo off
setlocal EnableDelayedExpansion

set "CC=clang-cl"
set "ASM=nasm"
set "LD=lld-link"

set "BUILD_DIR=build"
set "CC_LOG_FILE=compile_commands.json"
set "CC_LOG_TMP=compile_commands.tmp"
set "OUT=program.exe"

set "RUNTIME_DIR=%CD%\runtime"
set "RUNTIME_DIR=!RUNTIME_DIR:\=\\!"
set "CFLAGS=/D_CRT_SECURE_NO_WARNINGS /nologo /c /GS- /W3 /Oi /O2 /Zc:inline /Zc:forScope /FC /EHa /GR- /clang:-std=c23 /I !RUNTIME_DIR!"
set "ASMFLAGS=-f win64"
set "LDFLAGS=/SUBSYSTEM:CONSOLE /ENTRY:_start /BASE:0x400000 /NODEFAULTLIB /NOLOGO"

if "%~1"=="" (
    echo Usage: %~nx0 [build ^| clean ^| reset ^| run ]
    goto :EOF
)

if /I "%~1"=="build" goto build
if /I "%~1"=="clean" goto clean
if /I "%~1"=="reset" goto reset
if /I "%~1"=="run" goto run

echo Unknown command: %~1
goto :EOF

:init_log
echo [ > "%CC_LOG_TMP%"
goto :EOF

:finalize_log
powershell -Command "(Get-Content %CC_LOG_TMP% -Raw) -replace ',\s*$','' | Set-Content %CC_LOG_FILE%"
echo ] >> "%CC_LOG_FILE%"
del "%CC_LOG_TMP%" >nul 2>&1
goto :EOF

:build
echo ========================================================
echo Starting build...
echo ========================================================

call :init_log

if not exist "%BUILD_DIR%" mkdir "%BUILD_DIR%"

for /R "runtime" %%F in (*.hashrec) do (
    set "header=%%F"
    set "header=!header:.hashrec=.h!"
    echo [Parsing] %%F -> !header!
    python parse_hashrec.py "%%F" "!header!"
)

for /R "runtime" %%F in (*.c) do (
    set "full=%%F"
    set "rel=!full:%CD%\=!"
    if "!rel:~0,1!"=="\" set "rel=!rel:~1!"
    set "obj=%BUILD_DIR%\!rel:.c=.obj!"
    for %%G in ("!obj!") do (
        if not exist "%%~dpG" mkdir "%%~dpG"
    )
    echo [Compiling C] %%F
    %CC% %CFLAGS% /Fo"!obj!" "%%F"

    for %%A in ("%%F") do set "abs_file=%%~fA"
    set "file_escaped=!abs_file:\=\\!"


    set "obj_escaped=!obj:\=\\!"

    set "cmd=%CC% %CFLAGS% /c %%F /Fo!obj!"
    set "cmd_escaped=!cmd:\=\\!"

    set "dir_escaped=%CD%"
    set "dir_escaped=!dir_escaped:\=\\!"

    >>"%CC_LOG_TMP%" echo { "directory": "!dir_escaped!", "command": "!cmd_escaped!", "file": "!file_escaped!" },

    %CC% %CFLAGS% /Fo"!obj!" "%%F"
)

for /R "runtime" %%F in (*.asm) do (
    set "full=%%F"
    set "rel=!full:%CD%\=!"
    if "!rel:~0,1!"=="\" set "rel=!rel:~1!"
    set "obj=%BUILD_DIR%\!rel:.asm=.obj!"
    for %%G in ("!obj!") do (
        if not exist "%%~dpG" mkdir "%%~dpG"
    )
    echo [Assembling] %%F
    %ASM% %ASMFLAGS% -o "!obj!" "%%F"
)

rem REMOVE THIS ONCE COMPILING INTO A STATIC LIBRARY

for /R "tests" %%F in (*.c) do (
    set "full=%%F"
    set "rel=!full:%CD%\=!"
    if "!rel:~0,1!"=="\" set "rel=!rel:~1!"
    set "obj=%BUILD_DIR%\!rel:.c=.obj!"
    for %%G in ("!obj!") do (
        if not exist "%%~dpG" mkdir "%%~dpG"
    )
    echo [Compiling C test] %%F
    %CC% %CFLAGS% /Fo"!obj!" "%%F"

    for %%A in ("%%F") do set "abs_file=%%~fA"
    set "file_escaped=!abs_file:\=\\!"


    set "obj_escaped=!obj:\=\\!"

    set "cmd=%CC% %CFLAGS% /c %%F /Fo!obj!"
    set "cmd_escaped=!cmd:\=\\!"

    set "dir_escaped=%CD%"
    set "dir_escaped=!dir_escaped:\=\\!"

    >>"%CC_LOG_TMP%" echo { "directory": "!dir_escaped!", "command": "!cmd_escaped!", "file": "!file_escaped!" },

    %CC% %CFLAGS% /Fo"!obj!" "%%F"
)

for /R "tests" %%F in (*.asm) do (
    set "full=%%F"
    set "rel=!full:%CD%\=!"
    if "!rel:~0,1!"=="\" set "rel=!rel:~1!"
    set "obj=%BUILD_DIR%\!rel:.asm=.obj!"
    for %%G in ("!obj!") do (
        if not exist "%%~dpG" mkdir "%%~dpG"
    )
    echo [Assembling test] %%F
    %ASM% %ASMFLAGS% -o "!obj!" "%%F"
)

set "objfiles="
for /R "%BUILD_DIR%" %%F in (*.obj) do (
    set "objfiles=!objfiles! "%%F""
)
echo [Linking] Creating %OUT%
%LD% %LDFLAGS% /OUT:%OUT% %objfiles%

call :finalize_log

echo ========================================================
echo Build complete: %OUT%
echo ========================================================
goto :EOF

:clean
cls
echo ========================================================
echo Cleaning up...
if exist %BUILD_DIR% rmdir /s /q "%BUILD_DIR%"
if exist "%OUT%" del /q "%OUT%"
echo ========================================================
goto :EOF

:reset
call "%~0" clean
call "%~0" build
goto :EOF

:run
echo ========================================================
echo Running....
echo ====================== STDOUT ==========================
%OUT%
echo ========================================================
echo Process exited with error code: %ErrorLevel%
goto :EOF