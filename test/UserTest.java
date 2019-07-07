import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class UserTest {

    @Test
    void constructors(){
        assertThrows(NullPointerException.class,() -> {new User(null,"pwd");});
        assertThrows(NullPointerException.class,() -> {new User("Mario",null);});
        assertThrows(NullPointerException.class,() -> {new User(null,null);});
        assertThrows(IllegalArgumentException.class,() -> {new User("","pwd");});
        assertThrows(IllegalArgumentException.class,() -> {new User("Mario","");});
        assertThrows(IllegalArgumentException.class,() -> {new User("","");});

        User u1 = new User("Mario");
        assertFalse(u1.hasPassword());
        assertThrows(IllegalInvocationException.class,()->{u1.auth("pwd");});
        User u2 = new User("Luigi","pwd");
        assertTrue(u2.hasPassword());
        assertTrue(u2.auth("pwd"));
    }

    @Test
    void auth() {
        User u1 = new User("Mario");
        User u2 = new User("Luigi","pwd");

        assertThrows(NullPointerException.class,() -> {u1.auth(null);});
        assertThrows(IllegalArgumentException.class,() -> {u1.auth("");});
        assertThrows(IllegalInvocationException.class,() -> {u1.auth("pwd");});

        assertFalse(u2.auth("pwd_err"));
        assertTrue(u2.auth("pwd"));
    }

    @Test
    void getId() {
        User u1 = new User("Mario");
        User u2 = new User("Luigi","pwd");
        assertEquals("Mario",u1.getId());
        assertEquals("Luigi",u2.getId());
    }

    @Test
    void hasPassword() {
        User u1 = new User("Mario");
        User u2 = new User("Luigi","pwd");
        assertFalse(u1.hasPassword());
        assertTrue(u2.hasPassword());
        u1.setPassword("pwd");
        assertTrue(u1.hasPassword());
    }

    @Test
    void setPassword() {
        User u1 = new User("Mario");
        User u2 = new User("Luigi","pwd");

        assertThrows(NullPointerException.class,()->{u1.setPassword(null);});
        assertThrows(IllegalArgumentException.class,()->{u1.setPassword("");});
        assertThrows(IllegalInvocationException.class,()->{u2.setPassword("pwd_1");});

        u1.setPassword("pwd");
        assertTrue(u1.auth("pwd"));
    }

    @Test
    void changePassword() {
        User u1 = new User("Mario");
        User u2 = new User("Luigi","pwd");

        assertThrows(NullPointerException.class,()->{u1.changePassword(null,"pwd_1");});
        assertThrows(NullPointerException.class,()->{u1.changePassword("pwd",null);});
        assertThrows(NullPointerException.class,()->{u1.changePassword(null,null);});
        assertThrows(IllegalArgumentException.class,()->{u1.changePassword("","pwd_1");});
        assertThrows(IllegalArgumentException.class,()->{u1.changePassword("pwd","");});
        assertThrows(IllegalInvocationException.class,()->{u1.changePassword("pwd","pwd_1");});

        u1.setPassword("pwd");
        u1.changePassword("pwd","pwd_1");
        assertFalse(u1.auth("pwd"));
        assertTrue(u1.auth("pwd_1"));

        assertTrue(u2.auth("pwd"));
        u2.changePassword("pwd","pwd_1");
        assertFalse(u2.auth("pwd"));
        assertTrue(u2.auth("pwd_1"));
    }
    @Test
    void equals() {
        User u1 = new User("Mario");
        User u2 = new User("Luigi","pwd");
        User u3 = new User("Mario","pwd");
        User u4 = new User("Luigi","pwd");

        assertNotEquals(u1, u2);
        assertEquals(u1, u3);
        assertEquals(u2, u4);
    }
}