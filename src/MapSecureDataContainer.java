import javax.security.auth.login.CredentialException;
import java.io.*;
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
        assert repInv();
        if(!userAuth(Owner,passw)) throw new CredentialException("valid users' credentials are required !");
        if(file == null) throw new NullPointerException("file must be != null !");

        boolean added = dataSet.add(file);
        if(added){ //verifica se file è stato aggiunto.
            User usr = new User(Owner,passw);
            Map<User,AccessLevel> mapAcc = new HashMap<>();
            mapAcc.put(usr,AccessLevel.W);

            owners.put(file,usr);
            accesses.put(file,mapAcc);
        }

        assert repInv();
        return added;
    }

    /*
    Ottiene una copia del file nella collezione
    se vengono rispettati i controlli di identità
    @requires Owner != null && passw != null && !Owner.isEmpty() && !passw.isEmpty() && file != null &&
              (Exist (u,d) appartenente a (D * U) tale che u.id = Id && u.password = passw &&
              (Access((u,d)) = w || Access((u,d)) = r) )
    @throws NullPointerException se Id = null || passw = null || file = null
    @throws IllegalArgumentException se Owner.isEmpty() || passw.isEmpty() || file non in D
    @throws CredentialException se Not (Exist u appartenente a U tale che u.id = Id && u.password = passw)
    @throws NoAccessException se (Exist u appartenente a U tale che u.id = Owner && u.password = passw) &&
                                 Not (Exist (u,d) appartenente a (D * U) tale che u.id = Id && u.password = passw &&
                                      (Access((u,d)) = w || Access((u,d)) = r) )
    @return se file è presente restituisce una copia del file
    */
    @Override
    public E get(String Owner, String passw, E file) throws NullPointerException, IllegalArgumentException, CredentialException, NoAccessException {
        assert repInv();
        if(!userAuth(Owner,passw)) throw new CredentialException("valid users' credentials are required !");
        if(file == null) throw new NullPointerException("file must be != null !");
        if(!dataSet.contains(file)) throw new IllegalArgumentException("file must be inside data collection!");
        AccessLevel lev = accesses.get(file).get(Owner);
        if(lev == AccessLevel.U) throw new NoAccessException("user " + Owner + " has no access to file");

        Iterator<E> iterData = dataSet.iterator();
        E res = null;
        while (iterData.hasNext()) {
            res = iterData.next();
            if(res.equals(file)) break;
        }

        assert res != null;
        assert repInv();
        return res;
    }

    /*
    Rimuove il file nella collezione
    se vengono rispettati i controlli di identità
    @requires Owner != null && passw != null && !Owner.isEmpty() && !passw.isEmpty() && file != null
              (Exist u appartenente a U tale che u.id = Owner && u.password = passw && OwnedData(u) contiene file)
    @throws NullPointerException se Owner = null || passw = null || file = null
    @throws IllegalArgumentException se Owner.isEmpty() || passw.isEmpty()
    @throws CredentialException se Not (Exist u appartenente a U tale che u.id = Owner && u.password = passw)
    @throws NoAccessException se (Exist u appartenente a U tale che u.id = Owner && u.password = passw) &&
            Not (Exist u appartenente a U tale che u.id = Owner && u.password = passw && OwnedData(u) contiene file)
    @modifies this
    @effects this_post.D = this_pre.D - file
    @return restituisce una copia di file prima di rimuoverlo da D
     */
    @Override
    public E remove(String Owner, String passw, E file) throws NullPointerException, IllegalArgumentException, CredentialException, NoAccessException {
        assert repInv();
        if(!userAuth(Owner,passw)) throw new CredentialException("valid users' credentials are required !");
        if(file == null) throw new NullPointerException("file must be != null !");
        if(!dataSet.contains(file)) throw new IllegalArgumentException("file must be inside data collection!");
        if(owners.get(file).equals(Owner)) throw new NoAccessException("user " + Owner + " must be the Owner to remove file!");

        Iterator<E> iterData = dataSet.iterator();
        E res = null;
        while (iterData.hasNext()) {
            res = iterData.next();
            if(res.equals(file)) {
                iterData.remove();
                owners.remove(res);
                accesses.remove(res);
                break;
            }
        }

        assert res != null;
        assert repInv();
        return res;
    }
    /*
    Crea una copia del file nella collezione
    se vengono rispettati i controlli di identità
    @requires Owner != null && passw != null && !Owner.isEmpty() && !passw.isEmpty() && file != null &&
              Not (Exist d in D. d.path = newFilePath) &&
              (Exist u appartenente a U tale che u.id = Owner && u.password = passw && OwnedData(u) contiene file)
    @throws NullPointerException se Owner = null || passw = null || file = null
    @throws IllegalArgumentException se Owner.isEmpty() || passw.isEmpty() || Exist d in D. d.path = newFilePath
    @throws CredentialException se Not (Exist u appartenente a U tale che u.id = Owner && u.password = passw)
    @throws NoAccessException se (Exist u appartenente a U tale che u.id = Owner && u.password = passw) &&
            Not (Exist u appartenente a U tale che u.id = Owner && u.password = passw && OwnedData(u) contiene file)
    @modifies this
    @effects effettua una copia di file
     */
    @Override
    public void copy(String Owner, String passw, E file, String newFilePath) throws NullPointerException, IllegalArgumentException, CredentialException, NoAccessException {
        assert repInv();
        if(!userAuth(Owner,passw)) throw new CredentialException("valid users' credentials are required !");
        if(file == null) throw new NullPointerException("file must be != null !");
        if(!dataSet.contains(file)) throw new IllegalArgumentException("file must be inside data collection!");
        if(!owners.get(file).equals(Owner)) throw new NoAccessException("user " + Owner + " must be the Owner to copy file!");
        if(dataSet.contains(newFilePath)) throw new IllegalArgumentException("newfilePath must be unique inside data collection!");

        put(Owner,passw, (E) new SecureFile(newFilePath));

        assert repInv();
    }

    /*
    Condivide in lettura il file nella collezione con un altro utente
    se vengono rispettati i controlli di identità
    @requires Owner != null && passw != null && Other!=null && !Owner.isEmpty() && !passw.isEmpty() && !Other.isEmpty()
              && file != null &&
              (Exist u appartenente a U tale che u.id = Owner && u.password = passw && OwnedData(u) contiene file) &&
              (Exist u appartenente a U tale che u.id = Other)
    @throws NullPointerException se Owner = null || passw = null || Other = null || file = null
    @throws IllegalArgumentException se Owner.isEmpty() || passw.isEmpty() || Other.isEmpty()
    @throws CredentialException se Not (Exist u appartenente a U tale che u.id = Owner && u.password = passw)
    @throws UnknownUserException Not (Exist u appartenente a U tale che u.id = Other)
    @throws NoAccessException se (Exist u appartenente a U tale che u.id = Owner && u.password = passw) &&
            Not (Exist u appartenente a U tale che u.id = Owner && u.password = passw && OwnedData(u) contiene file)
    @modifies this
    @effects u= {Other, passw}, Access(u,file) = r
     */
    @Override
    public void shareR(String Owner, String passw, String Other, E file) throws NullPointerException, IllegalArgumentException, CredentialException, UnknownUserException, NoAccessException {
        assert repInv();
        if(!userAuth(Owner,passw)) throw new CredentialException("valid users' credentials are required !");
        if(Other == null) throw new NullPointerException("Other must be != null !");
        if(Other.isEmpty()) throw new IllegalArgumentException("Other can't be empty!");
        if(file == null) throw new NullPointerException("file must be != null !");
        if(!dataSet.contains(file)) throw new IllegalArgumentException("file must be inside data collection!");
        if(!owners.get(file).equals(Owner)) throw new NoAccessException("user " + Owner + " must be the Owner to share file!");
        if(!users.contains(Other)) throw new UnknownUserException("you are trying to share a file with " + Other + " who is not inside the collection!");

        User otherUser = getUser(Other);
        accesses.get(file).put(otherUser,AccessLevel.R);

        assert repInv();
    }

    /*
    Condivide in lettura e scrittura il file nella collezione con un altro utente
    se vengono rispettati i controlli di identità
    @requires Owner != null && passw != null && Other!=null && !Owner.isEmpty() && !passw.isEmpty() && !Other.isEmpty()
              && file != null &&
              (Exist u appartenente a U tale che u.id = Owner && u.password = passw && OwnedData(u) contiene file) &&
              (Exist u appartenente a U tale che u.id = Other)
    @throws NullPointerException se Owner = null || passw = null || Other = null || file = null
    @throws IllegalArgumentException se Owner.isEmpty() || passw.isEmpty() || Other.isEmpty()
    @throws CredentialException se Not (Exist u appartenente a U tale che u.id = Owner && u.password = passw)
    @throws UnknownUserException Not (Exist u appartenente a U tale che u.id = Other)
    @throws NoAccessException se (Exist u appartenente a U tale che u.id = Owner && u.password = passw) &&
            Not (Exist u appartenente a U tale che u.id = Owner && u.password = passw && OwnedData(u) contiene file)
    @modifies this
    @effects u= {Other, passw}, Access(u,file) = w
     */
    @Override
    public void shareW(String Owner, String passw, String Other, E file) throws NullPointerException, IllegalArgumentException, CredentialException, UnknownUserException, NoAccessException {
        assert repInv();
        if(!userAuth(Owner,passw)) throw new CredentialException("valid users' credentials are required !");
        if(Other == null) throw new NullPointerException("Other must be != null !");
        if(Other.isEmpty()) throw new IllegalArgumentException("Other can't be empty!");
        if(file == null) throw new NullPointerException("file must be != null !");
        if(!dataSet.contains(file)) throw new IllegalArgumentException("file must be inside data collection!");
        if(!owners.get(file).equals(Owner)) throw new NoAccessException("user " + Owner + " must be the Owner to share file!");
        if(!users.contains(Other)) throw new UnknownUserException("you are trying to share a file with " + Other + " who is not inside the collection!");

        User otherUser = getUser(Other);
        accesses.get(file).put(otherUser,AccessLevel.W);

        assert repInv();
    }

    /*
    Restituisce un iteratore (senza remove) che genera tutti i file
    dell’utente in ordine arbitrario
    se vengono rispettati i controlli di identità
    @requires Owner != null && passw != null && !Owner.isEmpty() && !passw.isEmpty() &&
              (Exist u appartenente a U tale che u.id = Owner && u.password = passw)
    @throws NullPointerException se Owner = null || passw = null
    @throws IllegalArgumentException se Owner.isEmpty() || passw.isEmpty()
    @throws CredentialException se Not (Exist u appartenente a U tale che u.id = Owner && u.password = passw)
    @return Restituisce un iteratore (senza remove) che genera tutti i file dell’utente in ordine arbitrario
    */
    @Override
    public Iterator<E> getIterator(String Owner, String passw) throws NullPointerException, IllegalArgumentException, CredentialException {
        if(!userAuth(Owner,passw)) throw new CredentialException("valid users' credentials are required !");

        Set<E> res = new HashSet<>();
        Iterator<Map.Entry<E,User>> iterOwners = owners.entrySet().iterator();
        while (iterOwners.hasNext()) {
            Map.Entry<E,User> entry = iterOwners.next();
            if(entry.getValue().equals(Owner)) {
                res.add(entry.getKey());
            }
        }

        return new NoRemoveIterator<E>(res.iterator());
    }

    /*
    Memorizza file nel file relativo
    @requires Id != null && passw != null && !Id.isEmpty() && !passw.isEmpty() && file != null &&
              (Exist (u,d) appartenente a U tale che u.id = Id && u.password = passw && d = file && Access(u,d) = w)
    @throws NullPointerException se Id = null || passw = null || file = null
    @throws IllegalArgumentException se Id.isEmpty() || passw.isEmpty()
    @throws CredentialException se Not (Exist u appartenente a U tale che u.id = Id && u.password = passw)
    @throws NoAccessException se (Exist u appartenente a U tale che u.id = Id && u.password = passw) &&
            Not (Exist (u,d) appartenente a U tale che u.id = Id && u.password = passw && d = file && Access(u,d) = w)
    @throws IOException se si verifica un problema durante la scrittura su file
    @modifies this, file
    @effects scrivi contenuto di file nel file associato
     */
    @Override
    public void storeFile(String Id, String passw, E file) throws NullPointerException, IllegalArgumentException, CredentialException, NoAccessException, IOException {
        assert repInv();
        if(!userAuth(Id,passw)) throw new CredentialException("valid users' credentials are required !");
        if(file == null) throw new NullPointerException("file must be != null !");
        if(!dataSet.contains(file)) throw new IllegalArgumentException("file must be inside data collection!");
        if(accesses.get(file).get(Id) != AccessLevel.W) throw new NoAccessException("user " + Id + " must have write access to file!");
        // Serialization

        //Salvo oggetto file nel file relativo
        file = getFile(file.getFilePath());
        FileOutputStream f = new FileOutputStream(file.getFilePath());
        ObjectOutputStream out = new ObjectOutputStream(f);

        out.writeObject(file);

        out.close();
        f.close();

        System.out.println("Object has been serialized");
        assert repInv();
    }
    /*
    Leggi file dal file relativo
    @requires Id != null && passw != null && !Id.isEmpty() && !passw.isEmpty() && file != null &&
              (Exist (u,d) appartenente a U tale che u.id = Id && u.password = passw && d = file && Access(u,d) = w)
    @throws NullPointerException se Id = null || passw = null || file = null
    @throws IllegalArgumentException se Id.isEmpty() || passw.isEmpty()
    @throws CredentialException se Not (Exist u appartenente a U tale che u.id = Id && u.password = passw)
    @throws NoAccessException se (Exist u appartenente a U tale che u.id = Id && u.password = passw) &&
            Not (Exist (u,d) appartenente a U tale che u.id = Id && u.password = passw && d = file && Access(u,d) = w)
    @throws IOException se si verifica un problema durante la scrittura su file
    @modifies this, file
    @effects recupera contenuto di file da file associato
    */
    @Override
    public void readFile(String Id, String passw, E file) throws NullPointerException, IllegalArgumentException, CredentialException, NoAccessException, IOException, ClassNotFoundException {
        assert repInv();
        if(!userAuth(Id,passw)) throw new CredentialException("valid users' credentials are required !");
        if(file == null) throw new NullPointerException("file must be != null !");
        if(!dataSet.contains(file)) throw new IllegalArgumentException("file must be inside data collection!");
        if(accesses.get(file).get(Id) == AccessLevel.U) throw new NoAccessException("user " + Id + " must have read access to file!");
        // Deserialization

        file = getFile(file.getFilePath());
        FileInputStream f = new FileInputStream(file.getFilePath());
        ObjectInputStream in = new ObjectInputStream(f);

        file = (E) in.readObject();
        dataSet.remove(file);
        dataSet.add(file);

        in.close();
        f.close();

        System.out.println("Object has been serialized");
        assert repInv();
    }

    /*
    Verifica se esiste un utente u con u.id = id
    @requires Id != null && !Id.isEmpty()
    @throws NullPointerException se Id = null || passw = null
    @throws IllegalArgumentException se Id.isEmpty()
    @return true se esiste un utente u tale che u.id = Id; false altrimenti
    */
    public boolean userExist(String Id) throws NullPointerException, IllegalArgumentException {
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
    public boolean userAuth(String Id, String passw) throws NullPointerException, IllegalArgumentException {
        if(Id == null) throw new NullPointerException("Id must be != null !");
        if(Id.isEmpty()) throw new IllegalArgumentException("Id can't be empty!");
        if(passw == null) throw new NullPointerException("passw must be != null !");
        if(passw.isEmpty()) throw new IllegalArgumentException("passw can't be empty!");
        for (User u : users) {
            if(u.getId().equals(Id) && u.auth(passw)) return true;
        }
        return false;
    }

    private User getUser(String Id){
        Iterator<User> iterUsers = users.iterator();
        User res = null;
        while (iterUsers.hasNext()) {
            res = iterUsers.next();
            if(res.equals(Id)) break;
        }
        return res;
    }

    private E getFile(String filePath){
        Iterator<E> iterFile = dataSet.iterator();
        E res = null;
        while (iterFile.hasNext()) {
            res = iterFile.next();
            if(res.equals(filePath)) break;
        }
        return res;
    }
}