@echo off
REM Build implant.jar — requires JDK 11+ on PATH
javac Main.java
if errorlevel 1 (echo [FAIL] javac failed & exit /b 1)
jar cfe implant.jar Main Main.class
if errorlevel 1 (echo [FAIL] jar failed & exit /b 1)
echo [OK] implant.jar built
del Main.class
