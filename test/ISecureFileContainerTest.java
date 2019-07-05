import org.junit.jupiter.api.Test;

import java.util.HashSet;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

class Exam_SecureWrap extends SecureFile{
    public String name;
    public int grade;

    Exam_SecureWrap(String p_filePath, String p_name, int p_grade) throws NullPointerException, IllegalArgumentException {
        super(p_filePath);
        name = p_name;
        grade = p_grade;
    }

}


class ISecureFileContainerTest {
    private final String testFolderPath = "~/Desktop/SecureFileContainer_test/";


    @Test
    void users() {
        User u = new User("Luca","pwd");
        User u2 = new User("Luca","pwd2");
        User u3 = new User("Marco","pwd2");
        Set<User> users = new HashSet<>();
        assertTrue(users.add(u));
        assertTrue(users.contains(u));
        assertTrue(users.contains(u2));
        assertTrue(users.contains("Luca"));


        assertFalse(users.add(u2));
        assertTrue(users.add(u3));
        assertTrue(users.contains("Luca"));


        assertTrue(u.auth("pwd"));
        assertFalse(u.auth("pwd_err"));
        assertTrue(u.equals(u2));
        assertTrue(u.equals("Luca"));
        assertTrue(u.equals(u2));
        assertFalse(u.equals("Marco"));
    }

    @Test
    void createUser() {
        ISecureFileContainer<Exam_SecureWrap> data = new MapSecureDataContainer<Exam_SecureWrap>();

        assertThrows(NullPointerException.class,() -> { data.createUser(null, "asd");});
        assertThrows(NullPointerException.class,() -> { data.createUser("asd", null);});
        assertThrows(IllegalArgumentException.class,() -> { data.createUser("", "asd");});
        assertThrows(IllegalArgumentException.class,() -> { data.createUser("asd", "");});

        data.createUser("Luca"," pwd");

        assertThrows(DuplicatedUserException.class,() -> { data.createUser("Luca", "pwd2");});
        data.createUser("Maria"," pwd");
    }

    @Test
    void removeUser() {
    }

    @Test
    void getSize() {
    }

    @Test
    void put() {
    }

    @Test
    void get() {
    }

    @Test
    void remove() {
    }

    @Test
    void copy() {
    }

    @Test
    void shareR() {
    }

    @Test
    void shareW() {
    }

    @Test
    void getIterator() {
    }

    @Test
    void storeFile() {
    }

    @Test
    void readFile() {
    }

    @Test
    void userExist() {
    }

    @Test
    void userAuth() {
    }
}