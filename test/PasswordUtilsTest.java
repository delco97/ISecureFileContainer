import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class PasswordUtilsTest {

    @Test
    void hashPassword() {
        //Controllo dei requisiti
        assertThrows(NullPointerException.class,() -> PasswordUtils.hashPassword(null));
        assertThrows(IllegalArgumentException.class,() -> PasswordUtils.hashPassword(""));

        String superSecurePassword = "password";
        String hashedPwd = PasswordUtils.hashPassword(superSecurePassword);
        assertEquals(hashedPwd,PasswordUtils.hashPassword("password"));
    }

    @Test
    void verifyPassword() {
        //Controllo dei requisiti
        assertThrows(NullPointerException.class,() -> PasswordUtils.verifyPassword(null,"asd"));
        assertThrows(NullPointerException.class,() -> PasswordUtils.verifyPassword("asd",null));
        assertThrows(NullPointerException.class,() -> PasswordUtils.verifyPassword(null,null));
        assertThrows(IllegalArgumentException.class,() -> PasswordUtils.verifyPassword("asd",""));
        assertThrows(IllegalArgumentException.class,() -> PasswordUtils.verifyPassword("","asd"));

        String superSecurePassword = "password";
        String hashedPwd = PasswordUtils.hashPassword(superSecurePassword);

        assertTrue(PasswordUtils.verifyPassword("password",hashedPwd));
        assertFalse(PasswordUtils.verifyPassword("Password",hashedPwd));
        assertFalse(PasswordUtils.verifyPassword(" password",hashedPwd));
    }
}