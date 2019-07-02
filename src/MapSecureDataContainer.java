import jdk.nashorn.internal.runtime.Debug;

import javax.security.auth.login.CredentialException;
import java.util.*;

public class MapSecureDataContainer<E extends SecureFile> extends SecureFile implements ISecureFileContainer<E>{
    /*
     AF(c):
        U = c.users
        D = c.dataSet
        A = c.AccessLevel
        
        
        Owner = c.owners
        Access = c.accesses
     
     IR:
        users != null && dataSet!= null && owners != null && accesses != null &&
        owners.keySet = dataSet && accesses.keySet = dataSet &&
        owners.values sottoinsieme di users &&
        For all map. map in accesses.values => map.keySet sottoinsieme di users
     */

    //private Set<User> users;
    //private Set<E> dataSet;
    //private Map<E,User> owners;

    private Map<E,Map<User,AccessLevel>> accesses;
    private Set<User> users;
    private Set<E> dataSet;
    private Map<E,User> owners;
    private Map<E,Map<User,AccessLevel>> accesses;


    MapSecureDataContainer(String p_filePath) throws NullPointerException, IllegalArgumentException {
        super(p_filePath);
        users = new HashSet<>();
        dataSet = new HashSet<>();
        owners = new HashMap<>();
        accesses = new HashMap<>();
    }


    MapSecureDataContainer(SecureFile p_sFile) throws NullPointerException, IllegalArgumentException {
        super(p_sFile);
        users = new HashSet<>();
        dataSet = new HashSet<>();
        owners = new HashMap<>();
        accesses = new HashMap<>();
    }

    /*
    Verifica la condizione di IR
    @return true se IR = true; false altrimenti
     */
    private boolean repInv(){
        boolean ir;
        ir = users != null && dataSet != null && owners != null && accesses != null &&
             owners.keySet().equals(dataSet) && accesses.keySet().equals(dataSet) &&
             users.containsAll(owners.values());
        if(ir) {
            //For all map. map in accesses.values => map.keySet sottoinsieme di users
            for (Map<User, AccessLevel> map : accesses.values()) {
                if (!users.containsAll(map.keySet())) {
                    ir = false;
                    break;
                }
            }
        }
        return ir;
    }

    /*
    Crea l’identità di un nuovo utente della collezione
    @requires Id != null && passw != null && !Id.isEmpty() && !passw.isEmpty() &&
              Not (Exist u appartenente a U tale che u.id = Id)
    @throws NullPointerException se Id = null || passw = null
    @throws IllegalArgumentException se Id.isEmpty() || passw.isEmpty()
    @throws DuplicatedUserException se (Exist u appartenente a U tale che u.id = Id)
    @modifies this
    @effects u = {Id,passw} && this_post.U = this_pre.U + u
    */
    @Override
    public void createUser(String Id, String passw) throws NullPointerException, IllegalArgumentException, DuplicatedUserException {
        assert repInv();
        if(passw == null) throw new NullPointerException("passw must be != null !");
        if(passw.isEmpty()) throw new IllegalArgumentException("passw can't be empty!");
        if(userExist(Id)) throw new DuplicatedUserException("users id must be unique !");

        users.add(new User(Id,passw));

        assert repInv();
    }

    /*
     Rimuove l’utente dalla collezione
     @requires Id != null && passw != null && !Id.isEmpty() && !passw.isEmpty() &&
               (Exist u appartenente a U tale che u.id = Id && u.password = passw)
     @throws NullPointerException se Id = null || passw = null
     @throws IllegalArgumentException se Id.isEmpty() || passw.isEmpty()
     @throws CredentialException se Not (Exist u appartenente a U tale che u.id = Id && u.password = passw)
     @modifies this
     @effects u = {Id,passw} && this_post.U = this_pre.U - u &&
              this_post.D = this_pre.D - OwnedData(u)
     */
    @Override
    public void removeUser(String Id, String passw) throws NullPointerException, IllegalArgumentException, CredentialException {
        assert repInv();

        if(!userAuth(Id,passw)) throw new CredentialException("valid users' credentials are required !");

        assert users.remove(Id); //rimuovo utente da insime degli utenti presenti
        //L'insieme dei dati che prima appartenevano all'utente u con u.id = Id devono essere rimossi
        Iterator<Map.Entry<E,User>> iterOwners = owners.entrySet().iterator();
        while (iterOwners.hasNext()) {
            Map.Entry<E,User> entry = iterOwners.next();
            if(entry.getValue().equals(Id)){
                dataSet.remove(entry.getKey());
                accesses.remove(entry.getKey());
                iterOwners.remove();
            }
        }
        //Rimuovere eventuali accessi asseganti all'utente rimosso
        Iterator<Map.Entry<E,Map<User,AccessLevel>>> iterAccesses = accesses.entrySet().iterator();
        while (iterAccesses.hasNext()) {
            Map.Entry<E,Map<User,AccessLevel>> entry = iterAccesses.next();
            entry.getValue().remove(Id);
        }

        assert repInv();
    }

    /*
    Restituisce il numero dei file di un utente presenti nella
    collezione
    @requires Owner != null && passw != null && !Owner.isEmpty() && !passw.isEmpty() &&
              (Exist u appartenente a U tale che u.id = Owner && u.password = passw)
    @throws NullPointerException se Owner = null || passw = null
    @throws IllegalArgumentException se Owner.isEmpty() || passw.isEmpty()
    @throws CredentialException se Not (Exist u appartenente a U tale che u.id = Owner && u.password = passw)
    @return Dato u = {Owner,passw} restituisce |OwnedData(u)|
     */
    @Override
    public int getSize(String Owner, String passw) throws NullPointerException, IllegalArgumentException, CredentialException {
        assert repInv();
        if(!userAuth(Owner,passw)) throw new CredentialException("valid users' credentials are required !");
        int count = 0;
        Iterator<Map.Entry<E,User>> iterOwners = owners.entrySet().iterator();
        while (iterOwners.hasNext()) {
            Map.Entry<E,User> entry = iterOwners.next();
            if(entry.getValue().equals(Owner)) count++;
        }
        assert repInv();
        return count;
    }

    /*
    Inserisce il file nella collezione
    se vengono rispettati i controlli di identità
    @requires Owner != null && passw != null && !Owner.isEmpty() && !passw.isEmpty() && file != null &&
              (Exist u appartenente a U tale che u.id = Owner && u.password = passw)
    @throws NullPointerException se Owner = null || passw = null || file = null
    @throws IllegalArgumentException se Owner.isEmpty() || passw.isEmpty()
    @throws CredentialException se Not (Exist u appartenente a U tale che u.id = Owner && u.password = passw )
    @modifies this
    @effects Dato u = {Id,passw} se OwnedData(u) non contiene elementi uguali a file allora file viene inserito in
             OwnedData(u); altrimenti file non viene inserito
    @return Dato u = {Id,passw} restituisce true se file viene inserito in OwnedData(u), false altrimenti.
    */
    @Override
    public boolean put(String Owner, String passw, E file) throws NullPointerException, IllegalArgumentException, CredentialException {
        if(!userAuth(Owner,passw)) throw new CredentialException("valid users' credentials are required !");
        if(file == null) throw new NullPointerException("file must be != null !");



    }

    @Override
    public E get(String Owner, String passw, E file) throws NullPointerException, IllegalArgumentException, CredentialException, NoAccessException {
        return null;
    }

    @Override
    public E remove(String Owner, String passw, E file) throws NullPointerException, IllegalArgumentException, CredentialException, NoAccessException {
        return null;
    }

    @Override
    public void copy(String Owner, String passw, E file) throws NullPointerException, IllegalArgumentException, CredentialException, NoAccessException {

    }

    @Override
    public void shareR(String Owner, String passw, String Other, E file) throws NullPointerException, IllegalArgumentException, CredentialException, UnknownUserException, NoAccessException {

    }

    @Override
    public void shareW(String Owner, String passw, String Other, E file) throws NullPointerException, IllegalArgumentException, CredentialException, UnknownUserException, NoAccessException {

    }

    @Override
    public Iterator<E> getIterator(String Owner, String passw) throws NullPointerException, IllegalArgumentException, CredentialException {
        return null;
    }

    @Override
    public void storeFile(String Id, String passw, E file) throws NullPointerException, IllegalArgumentException, CredentialException, NoAccessException {

    }

    @Override
    public void readFile(String Id, String passw, E file) throws NullPointerException, IllegalArgumentException, CredentialException, NoAccessException {

    }
    /*
    Verifica se esiste un utente u con u.id = id
    @requires Id != null && !Id.isEmpty()
    @throws NullPointerException se Id = null || passw = null
    @throws IllegalArgumentException se Id.isEmpty()
    @return true se esiste un utente u tale che u.id = Id; false altrimenti
    */
    public boolean userExist(String Id) throws NullPointerException {
        if(Id == null) throw new NullPointerException("Id must be != null !");
        if(Id.isEmpty()) throw new IllegalArgumentException("Id can't be empty!");
        return users.contains(Id);
    }

    /*
    Verifica se esiste un utente u con u.id = id e u.password = passw
    @requires Id != null && passw != null && !Id.isEmpty() && !passw.isEmpty()
    @throws NullPointerException se Id = null || passw = null
    @throws IllegalArgumentException se Id.isEmpty() || passw.isEmpty()
    @return true se esiste un utente u tale che u.id = Id && u.password = passw; false altrimenti
    */
    public boolean userAuth(String Id, String passw) throws NullPointerException {
        if(Id == null) throw new NullPointerException("Id must be != null !");
        if(Id.isEmpty()) throw new IllegalArgumentException("Id can't be empty!");
        if(passw == null) throw new NullPointerException("passw must be != null !");
        if(passw.isEmpty()) throw new IllegalArgumentException("passw can't be empty!");
        for (User u : users) {
            if(u.getId().equals(Id) && u.auth(passw)) return true;
        }
        return false;
    }
}