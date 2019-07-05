import java.util.Objects;

public class User {

    /* Overview:
     * User è un tipo di dato che contiene le informazioni realtive ad un utente.
     */

    private String id;
    private String hash_pwd; //hash della password
    private String salt; //utilizzato per l'hashing

    /*
     * Crea un nuovo utente
     * @requires p_id != null && p_pwd != null && !p_id.isEmpty() && !p_pwd.isEmpty()
     * @throws NullPointerException se p_id = null || p_pwd = null
     */
    public User(String p_id, String p_pwd) throws NullPointerException, IllegalArgumentException{
        if(p_id == null) throw new NullPointerException("p_id must be != null !");
        if(p_pwd == null) throw new NullPointerException("p_pwd must be != null !");
        if(p_id.isEmpty()) throw new IllegalArgumentException("p_id can't be an empty string!");
        if(p_pwd.isEmpty()) throw new IllegalArgumentException("p_pwd can't be an empty string!");
        id = p_id;
        salt = PasswordUtils.generateSalt();
        hash_pwd = PasswordUtils.hashPassword(p_pwd,salt);
    }

    /* Check if candidatePwd is the correct password for this
     * @requires p_candidatePwd != null && !p_candidatePwd.isEmpty()
     * @throws IllegalArgumentException se p_id = null
     * @return true se la password è corretta, altrimenti false
     */
    public boolean auth(String p_candidatePwd) throws IllegalArgumentException{
        if(p_candidatePwd == null) throw new NullPointerException("p_candidatePwd must be != null !");
        if(p_candidatePwd.isEmpty()) throw new IllegalArgumentException("p_candidatePwd can't be an empty string!");
        return PasswordUtils.verifyPassword(p_candidatePwd,hash_pwd,salt);
    }
    /* Get id of this
     * @return id of this
     */
    public String getId() { return id; }

    @Override
    public String toString(){
        return id;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null) return false;
        if(getClass() != o.getClass()) {
            String aux = (String) o;
            id.equals(aux);
        }
        User user = (User) o;
        return id.equals(user.id);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id);
    }
}
