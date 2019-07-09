import Exceptions.IllegalInvocationException;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class UserTest {

    @Test
    void constructors(){
        //Test controllo sui requisiti
        assertThrows(NullPointerException.class,() -> {new User(null,"pwd");});
        assertThrows(NullPointerException.class,() -> {new User("Mario",null);});
        assertThrows(NullPointerException.class,() -> {new User(null,null);});
        assertThrows(IllegalArgumentException.class,() -> {new User("","pwd");});
        assertThrows(IllegalArgumentException.class,() -> {new User("Mario","");});
        assertThrows(IllegalArgumentException.class,() -> {new User("","");});
        //Creazione di un utente con password da impostare
        User u1 = new User("Mario");
        assertFalse(u1.hasPassword());
        assertThrows(IllegalInvocationException.class,()->{u1.auth("pwd");});
        //Creazione di un utente con password
        User u2 = new User("Luigi","pwd");
        assertTrue(u2.hasPassword());
        assertTrue(u2.auth("pwd"));
    }

    @Test
    void auth() {
        User u1 = new User("Mario");
        User u2 = new User("Luigi","pwd");
        //Test controllo sui requisiti
        assertThrows(NullPointerException.class,() -> {u1.auth(null);});
        assertThrows(IllegalArgumentException.class,() -> {u1.auth("");});
        //Verifica che venga sollvata un'eccezione se si prova ad autenticare un utente senza password
        assertThrows(IllegalInvocationException.class,() -> {u1.auth("pwd");});
        //Verifica che una password errata non venga considerata valida
        assertFalse(u2.auth("pwd_err"));
        //Verifica che la password corretta venga riconosciuta come valida
        assertTrue(u2.auth("pwd"));
        //Verifica che il riconoscimento della password sia case-sensitive
        assertFalse(u2.auth("PWD"));
        //Verifica che sia possibile autenticare un utente che in precedenza non aveva la password
        u1.setPassword("pwd");
        assertTrue(u1.auth("pwd"));
        //Verifica che sia possibile autenticare un utente dopo che la sua password è stata cambiata
        u1.changePassword("pwd","pwd_new");
        assertTrue(u1.auth("pwd_new"));

    }

    @Test
    void getId() {
        User u1 = new User("Mario");
        User u2 = new User("Luigi","pwd");
        //Verifica che l'id restituito sia lo stesso utilizzato per la creazione
        assertEquals("Mario",u1.getId());
        assertEquals("Luigi",u2.getId());
        assertNotEquals("mario",u1.getId());
        assertNotEquals("luigi",u2.getId());
        assertNotEquals("MARIO",u1.getId());
        assertNotEquals("LUIGI",u2.getId());
    }

    @Test
    void hasPassword() {
        User u1 = new User("Mario");
        User u2 = new User("Luigi","pwd");
        //Verificare che hasPassword sia sempre coerente
        assertFalse(u1.hasPassword());
        assertTrue(u2.hasPassword());
        u1.setPassword("pwd");
        u2.changePassword("pwd","pwd_new");
        assertTrue(u1.hasPassword());
        assertTrue(u2.hasPassword());
    }

    @Test
    void setPassword() {
        User u1 = new User("Mario");
        User u2 = new User("Luigi","pwd");
        //Verificare che
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
        //Test controllo sui requisiti
        assertThrows(NullPointerException.class,()->{u1.changePassword(null,"pwd_1");});
        assertThrows(NullPointerException.class,()->{u1.changePassword("pwd",null);});
        assertThrows(NullPointerException.class,()->{u1.changePassword(null,null);});
        assertThrows(IllegalArgumentException.class,()->{u1.changePassword("","pwd_1");});
        assertThrows(IllegalArgumentException.class,()->{u1.changePassword("pwd","");});
        assertThrows(IllegalInvocationException.class,()->{u1.changePassword("pwd","pwd_1");});
        //Verificare che sia possibile cambiare la password ad un utente e che sia possa autenticare con la nuova password
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
        User u3 = new User("Mario","pwd_2");
        User u4 = new User("luigi","pwd");
        //Verifica che due utenti siano considerati uguali solo in base al loro id
        assertNotEquals(u1, u2);
        assertEquals(u1, u3);
        assertNotEquals(u2, u4);
    }

    @Test
    void _toString() {
        User u1 = new User("Mario");
        User u2 = new User("Luigi","pwd");
        //Verifica che la rappresentazione in formato stringa di un utente sia uguale al suo id
        assertEquals("Mario",u1.toString());
        assertEquals("Luigi",u2.toString());
    }

}