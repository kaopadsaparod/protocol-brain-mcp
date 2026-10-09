@echo off
setlocal enabledelayedexpansion

echo ========================================================
echo   Protocol Brain - Local CI Runner (Windows CMD / BAT)
echo ========================================================
echo.

:: Detect Python executable
where py >nul 2>&1
if %ERRORLEVEL% equ 0 (
    set "PYTHON_EXE=py -3"
) else (
    where python >nul 2>&1
    if %ERRORLEVEL% equ 0 (
        set "PYTHON_EXE=python"
    ) else (
        echo [ERROR] Neither 'py' nor 'python' was found in PATH!
        exit /b 1
    )
)

echo [1/3] Detecting Python environment...
%PYTHON_EXE% --version
echo.

echo [2/3] Running Ruff Linter...
%PYTHON_EXE% -m ruff check .
if %ERRORLEVEL% neq 0 (
    echo.
    echo [FAIL] Ruff linter found issues!
    exit /b %ERRORLEVEL%
)
echo [PASS] All lint checks passed!
echo.

echo [3/3] Running Pytest Test Suite...
%PYTHON_EXE% -m pytest --tb=short
if %ERRORLEVEL% neq 0 (
    echo.
    echo [FAIL] Pytest test suite failed!
    exit /b %ERRORLEVEL%
)

echo.
echo ========================================================
echo   [SUCCESS] All tests and lint checks passed cleanly!
echo ========================================================
exit /b 0
