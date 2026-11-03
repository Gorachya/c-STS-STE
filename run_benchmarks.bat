@echo off
setlocal EnableDelayedExpansion

if /I not "%~1"=="fast" if /I not "%~1"=="full" (
    echo Usage: %~nx0 fast^|full
    exit /b 1
)

set MODE=%~1
set CSTE_BENCH_MODE=%MODE%

IF EXIST "target\criterion" (
    echo Clearing previous criterion benchmark cache...
    RMDIR /S /Q "target\criterion"
)

echo ========================================
echo    Step 1: Selecting poly threshold
echo           Scale: 4096
echo ========================================
set "POLY_LOG=%TEMP%\c-ste-poly-product-bench.txt"
cargo bench --bench poly_product > "%POLY_LOG%" 2>&1
if %ERRORLEVEL% NEQ 0 (
    type "%POLY_LOG%"
    echo Poly product threshold benchmark failed!
    exit /b %ERRORLEVEL%
)
type "%POLY_LOG%"
for /f "usebackq delims=" %%i in (`python find-poly-threshold.py "%POLY_LOG%"`) do set "CSTE_POLY_THRESHOLD=%%i"
if "%CSTE_POLY_THRESHOLD%"=="" (
    echo Failed to determine the optimal polynomial threshold!
    exit /b 1
)
echo Optimal poly product threshold: %CSTE_POLY_THRESHOLD%
echo Clearing poly-product benchmark data before full benchmarks...
IF EXIST "target\criterion\polynomial product" (
    RMDIR /S /Q "target\criterion\polynomial product"
)

echo.
echo ========================================
echo       Step 2: Running cargo bench
echo       Mode: %MODE%
echo ========================================
for %%b in (epoch hints preprocess bls aggregation ste) do (
    cargo bench --bench %%b
    if !ERRORLEVEL! NEQ 0 (
        echo Benchmark %%b failed!
        exit /b !ERRORLEVEL!
    )
)

echo.
echo ========================================
echo  Step 3: Generating benchmark results
echo ========================================
python generate-table.py %MODE%
if %ERRORLEVEL% NEQ 0 (
    echo Python script failed!
    exit /b %ERRORLEVEL%
)

echo.
echo Done! The results are saved in benchmark_results.md
pause
