#!/bin/sh
# Build implant.jar — requires JDK 11+
set -e
javac Main.java
jar cfe implant.jar Main Main.class
rm -f Main.class
echo "[OK] implant.jar built"
