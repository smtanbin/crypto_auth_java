import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;

public final class CryptoAuth {
    public static final class TokenResult {
        private final String token;
        private final String check;

        public TokenResult(String token, String check) {
            this.token = token;
            this.check = check;
        }

        public String getToken() {
            return token;
        }

        public String getCheck() {
            return check;
        }
    }

    public static final class VerifiedToken {
        private final String username;
        private final String password;

        public VerifiedToken(String username, String password) {
            this.username = username;
            this.password = password;
        }

        public String getUsername() {
            return username;
        }

        public String getPassword() {
            return password;
        }
    }

    private static final int TOTAL_LENGTH = 512;
    private static final int TOKEN_SEGMENT = 128;
    private static final int PW_PART_LENGTH = 64;
    private static final int PAD_PREFIX_DIGITS = 2;
    private static final int OFFSET_PW1 = 128;
    private static final int OFFSET_USERNAME = 192;
    private static final int OFFSET_PW2 = 320;
    private static final int OFFSET_UUID2 = 384;

    private static final String ALPHANUMERIC = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

    private static final SecureRandom RANDOM = new SecureRandom();

    private final byte[] secretKey;
    private final Base64.Encoder b64Encoder = Base64.getEncoder();
    private final Base64.Decoder b64Decoder = Base64.getDecoder();

    public CryptoAuth() {
        this("default_secret");
    }

    public CryptoAuth(String secret) {
        if (secret == null || secret.isEmpty()) {
            throw new IllegalArgumentException("CryptoAuth: secret must be a non-empty string.");
        }
        this.secretKey = sha256Bytes(secret);
    }

    public String generatePassword(String password) {
        return sha512(password);
    }

    public TokenResult request(String username, String password) {
        String raw = buildRawToken(username, password);
        return new TokenResult(encrypt(raw), md5(raw));
    }

    public VerifiedToken verify(TokenResult result) {
        if (result == null) {
            throw new IllegalArgumentException("CryptoAuth: token result is required.");
        }

        String raw = decrypt(result.getToken());

        if (!md5(raw).equals(result.getCheck())) {
            throw new IllegalArgumentException("CryptoAuth: integrity check failed - token may have been tampered with.");
        }

        if (raw.length() != TOTAL_LENGTH) {
            throw new IllegalArgumentException(
                    "CryptoAuth: unexpected raw token length " + raw.length() + " (expected " + TOTAL_LENGTH + ")."
            );
        }

        String username = removePad(raw.substring(OFFSET_USERNAME, OFFSET_PW2));
        String passwordHash = raw.substring(OFFSET_PW1, OFFSET_USERNAME) + raw.substring(OFFSET_PW2, OFFSET_UUID2);

        return new VerifiedToken(username, passwordHash);
    }

    private String buildRawToken(String username, String password) {
        String passwordHash = sha512(password);
        String raw = generateUUID()
                + passwordHash.substring(0, PW_PART_LENGTH)
                + addPad(username)
                + passwordHash.substring(PW_PART_LENGTH)
                + generateUUID();

        if (raw.length() != TOTAL_LENGTH) {
            throw new IllegalStateException("CryptoAuth: raw token length mismatch - got " + raw.length() + ".");
        }

        return raw;
    }

    private String addPad(String text) {
        if (text == null) {
            throw new IllegalArgumentException("CryptoAuth: username cannot be null.");
        }

        int maxBody = TOKEN_SEGMENT - PAD_PREFIX_DIGITS;
        if (text.length() > maxBody) {
            throw new IllegalArgumentException(
                    "CryptoAuth: username too long (" + text.length() + " chars, max " + maxBody + ")."
            );
        }

        String prefix = String.format("%02d", text.length());
        return prefix + text + randomAlphanumeric(maxBody - text.length());
    }

    private String removePad(String padded) {
        if (padded == null || padded.length() < PAD_PREFIX_DIGITS) {
            throw new IllegalArgumentException("CryptoAuth: padded segment too short to contain length prefix.");
        }

        int bodyLength;
        try {
            bodyLength = Integer.parseInt(padded.substring(0, PAD_PREFIX_DIGITS));
        } catch (NumberFormatException ex) {
            throw new IllegalArgumentException("CryptoAuth: invalid length prefix in padded segment.", ex);
        }

        if (bodyLength < 0) {
            throw new IllegalArgumentException("CryptoAuth: invalid length prefix in padded segment.");
        }

        int bodyEnd = PAD_PREFIX_DIGITS + bodyLength;
        if (bodyEnd > padded.length()) {
            throw new IllegalArgumentException("CryptoAuth: stated length exceeds segment size.");
        }

        return padded.substring(PAD_PREFIX_DIGITS, bodyEnd);
    }

    private String encrypt(String plaintext) {
        byte[] iv = new byte[12];
        RANDOM.nextBytes(iv);

        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(secretKey, "AES"), new GCMParameterSpec(128, iv));

            byte[] encrypted = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
            int tagLength = 16;
            int cipherLength = encrypted.length - tagLength;

            byte[] ciphertext = new byte[cipherLength];
            byte[] tag = new byte[tagLength];

            System.arraycopy(encrypted, 0, ciphertext, 0, cipherLength);
            System.arraycopy(encrypted, cipherLength, tag, 0, tagLength);

            return b64Encoder.encodeToString(iv)
                    + "."
                    + b64Encoder.encodeToString(tag)
                    + "."
                    + b64Encoder.encodeToString(ciphertext);
        } catch (GeneralSecurityException ex) {
            throw new IllegalStateException("CryptoAuth: encryption failed.", ex);
        }
    }

    private String decrypt(String token) {
        if (token == null || token.isEmpty()) {
            throw new IllegalArgumentException("CryptoAuth: token is required.");
        }

        String[] parts = token.split("\\.");
        if (parts.length != 3 || parts[0].isEmpty() || parts[1].isEmpty() || parts[2].isEmpty()) {
            throw new IllegalArgumentException("CryptoAuth: malformed encrypted token (expected iv.tag.data).");
        }

        byte[] iv = b64Decoder.decode(parts[0]);
        byte[] tag = b64Decoder.decode(parts[1]);
        byte[] ciphertext = b64Decoder.decode(parts[2]);

        byte[] encrypted = new byte[ciphertext.length + tag.length];
        System.arraycopy(ciphertext, 0, encrypted, 0, ciphertext.length);
        System.arraycopy(tag, 0, encrypted, ciphertext.length, tag.length);

        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(secretKey, "AES"), new GCMParameterSpec(128, iv));
            byte[] plaintext = cipher.doFinal(encrypted);
            return new String(plaintext, StandardCharsets.UTF_8);
        } catch (GeneralSecurityException ex) {
            throw new IllegalArgumentException("CryptoAuth: decryption failed.", ex);
        }
    }

    private String sha512(String value) {
        return hexDigest("SHA-512", value);
    }

    private String md5(String value) {
        return hexDigest("MD5", value);
    }

    private byte[] sha256Bytes(String value) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            return md.digest(value.getBytes(StandardCharsets.UTF_8));
        } catch (GeneralSecurityException ex) {
            throw new IllegalStateException("CryptoAuth: SHA-256 unavailable.", ex);
        }
    }

    private String hexDigest(String algorithm, String value) {
        try {
            MessageDigest md = MessageDigest.getInstance(algorithm);
            byte[] digest = md.digest(value.getBytes(StandardCharsets.UTF_8));

            StringBuilder sb = new StringBuilder(digest.length * 2);
            for (byte b : digest) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();
        } catch (GeneralSecurityException ex) {
            throw new IllegalStateException("CryptoAuth: hashing failed for " + algorithm + ".", ex);
        }
    }

    private String randomAlphanumeric(int length) {
        StringBuilder sb = new StringBuilder(length);
        for (int i = 0; i < length; i++) {
            int idx = RANDOM.nextInt(ALPHANUMERIC.length());
            sb.append(ALPHANUMERIC.charAt(idx));
        }
        return sb.toString();
    }

    private String generateUUID() {
        byte[] entropy = new byte[32];
        RANDOM.nextBytes(entropy);
        String mixed = b64Encoder.encodeToString(entropy) + randomAlphanumeric(16);
        return sha512(mixed);
    }
}
