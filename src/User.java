import Exceptions.IllegalInvocationException;

import java.io.Serializable;
import java.util.Objects;

public class User implements Serializable {

    /* Overview:
     * User è un tipo di dato che contiene le informazioni realtive ad un utente
     */

    private String id; //id utente
    private String hash_pwd; //hash della password
    //Perché è opportuno definire serialversionUID ?
    // -> https://stackoverflow.com/questions/285793/what-is-a-serialversionuid-and-why-should-i-use-it
    private static final long serialversionUID = 30L;
    /*
     * Crea un nuovo utente con password
     * @requires p_id != null && p_pwd != null && !p_id.isEmpty() && !p_pwd.isEmpty()
     * @throws NullPointerException se p_id = null || p_pwd = null
     * @throws IllegalArgumentException se p_id.isEmpty() || p_pwd.isEmpty()
     */
    public User(String p_id, String p_pwd) throws NullPointerException, IllegalArgumentException{
        if(p_id == null) throw new NullPointerException("p_id must be != null !");
        if(p_id.isEmpty()) throw new IllegalArgumentException("p_id can't be an empty string!");
        if(p_pwd == null) throw new NullPointerException("p_pwd must be != null !");
        if(p_pwd.isEmpty()) throw new IllegalArgumentException("p_pwd can't be an empty string!");

        id = p_id;
        hash_pwd = PasswordUtils.hashPassword(p_pwd);
    }

    /*
     * Crea un nuovo utente senza password
     * @requires p_id != null && !p_id.isEmpty()
     * @throws NullPointerException se p_id = null
     * @throws IllegalArgumentException se p_id.isEmpty()
     */
    public User(String p_id) throws NullPointerException, IllegalArgumentException{
        if(p_id == null) throw new NullPointerException("p_id must be != null !");
        if(p_id.isEmpty()) throw new IllegalArgumentException("p_id can't be an empty string!");

        id = p_id;
        hash_pwd = "";
    }

    /* Controlla se candidatePwd è la password corretta per this
     * @requires p_candidatePwd != null && !p_candidatePwd.isEmpty() && hasPassword()
     * @throws NullPointerException se p_candidatePwd = null
     * @throws IllegalArgumentException se p_candidatePwd.isEmpty()
     * @throws IllegalInvocationException se !hasPassword()
     * @return true se la password è corretta, altrimenti false
     */
    public boolean auth(String p_candidatePwd) throws NullPointerException, IllegalArgumentException, IllegalInvocationException {
        if(p_candidatePwd == null) throw new NullPointerException("p_candidatePwd must be != null !");
        if(p_candidatePwd.isEmpty()) throw new IllegalArgumentException("p_candidatePwd can't be an empty string!");
        if(!hasPassword()) throw new IllegalInvocationException("A password must be already set for this user! Use setPassword if want to set it for the first time");
        return PasswordUtils.verifyPassword(p_candidatePwd,hash_pwd);
    }

    /* Get id of this
     * @return id of this
     */
    public String getId() { return id; }

    /*
    Verifica se this ha una password
    @return true se this ha una password; false altrimenti
    */
    public boolean hasPassword(){ return !hash_pwd.isEmpty();}

    /* Imosta la password di this con p_pwd se non è stata ancora definita
     * @requires p_pwd != null && !p_pwd.isEmpty() && !hasPassword()
     * @throws NullPointerException se p_pwd = null
     * @throws IllegalArgumentException se p_pwd.isEmpty()
     * @throws IllegalInvocationException se hasPassword()
     * @modifies hash_pwd, salt
     * @effects definito salt e hash_pwd = hash(p_pwd,salt)
     */
    public void setPassword(String p_pwd) throws NullPointerException, IllegalArgumentException, IllegalInvocationException {
        if(p_pwd == null) throw new NullPointerException("p_pwd must be != null !");
        if(p_pwd.isEmpty()) throw new IllegalArgumentException("p_pwd can't be an empty string!");
        if(hasPassword()) throw new IllegalInvocationException("A password has been already set for this user! Use changePassword if want to change it");

        hash_pwd = PasswordUtils.hashPassword(p_pwd);
    }

    /* Cambia la password se ancora se ne è stata definita una
     * @requires p_pwd_old != null && p_pwd_new != null && !p_pwd_old.isEmpty() && !p_pwd_new.isEmpty() && hasPassword()
     * @throws NullPointerException se p_pwd_old = null || p_pwd_new = null
     * @throws IllegalArgumentException se p_pwd_old.isEmpty() || p_pwd_new.isEmpty()
     * @throws IllegalInvocationException se !hasPassword()
     * @modifies hash_pwd, salt
     * @effects definito nuovi salt e hash_pwd = hash(p_pwd_new,salt)
     */
    public boolean changePassword(String p_pwd_old, String p_pwd_new) throws NullPointerException, IllegalArgumentException, IllegalInvocationException{
        if(p_pwd_old == null) throw new NullPointerException("p_pwd_old must be != null !");
        if(p_pwd_old.isEmpty()) throw new IllegalArgumentException("p_pwd_old can't be an empty string!");
        if(p_pwd_new == null) throw new NullPointerException("p_pwd_new must be != null !");
        if(p_pwd_new.isEmpty()) throw new IllegalArgumentException("p_pwd_new can't be an empty string!");
        if(!hasPassword()) throw new IllegalInvocationException("A password must be already set for this user! Use setPassword if want to set it for the first time");

        if(!auth(p_pwd_old)) return false;
        hash_pwd = PasswordUtils.hashPassword(p_pwd_new);
        return true;
    }

    @Override
    public String toString(){
        return id;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        User user = (User) o;
        return id.equals(user.id);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id);
    }
}
