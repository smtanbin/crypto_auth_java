import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

class CryptoAuthTest {

    private final CryptoAuth mysticAuth = new CryptoAuth(
            "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsbdHoFyHiNEYjzL/6080\n" +
            "SQIDAQAB"
    );

    private final String user = "test_user";
    private final String password = "test_password";

    @Test
    void encryptDecryptFlow() {
        String hashPassword = mysticAuth.generatePassword(password);
        CryptoAuth.TokenResult encrypted = mysticAuth.request(user, password);

        assertNotNull(encrypted.getToken(), "token");
        assertNotNull(encrypted.getCheck(), "check");

        CryptoAuth.VerifiedToken decrypted = mysticAuth.verify(encrypted);

        assertEquals(user, decrypted.getUsername(), "username");
        assertEquals(hashPassword, decrypted.getPassword(), "password hash");
    }
}
