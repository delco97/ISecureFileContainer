import Exceptions.CredentialException;
import Exceptions.DuplicatedUserException;
import Exceptions.NoAccessException;
import Exceptions.UnknownUserException;

import java.io.*;
import java.util.*;

public class ListSecureDataContainer<E extends SecureFile> extends SecureFile implements ISecureFileContainer<E>  {
    /*
     AF(c):
        U = c.users
        D = c.data
        A = c.AccessLevel

        Owner(d) = c.owners(di) dove di è la posizione del dato d in data
        Access(d,u) = c.accesses(di) dove di è la posizione del dato d in data

     IR:
        users != null && dataSet!= null && owners != null && accesses != null && admin != null &&
        admin.hasPassword() && users.contains(admin) &&
        |dataSet| = |owners| = |accesses| &&
        Not (Exist d1 e d2. d1 != d2 && dataSet.contains(d1) && dataSet.contains(d2)) &&
        owners sottoinsieme di users &&
        For all map. map in accesses => map.keySet sottoinsieme di users
     */

    private User admin; //admin del container
    private Set<User> users; //Utenti presenti nel container
    private List<E> dataSet; //dati presenti nel container
    private List<User> owners; //proprietari dei dati presenti nel container
    private List<Map<User,AccessLevel>> accesses; //Livello di accesso ad ogni dato presente nel container asseganto a ogni utente nel container

    /*
    Inizializza container vuoto.
    p_filePath rappresenta il path assoluto nel quale l'intero container può essere memorizzato
    */
    ListSecureDataContainer(String p_filePath) throws NullPointerException, IllegalArgumentException {
        super(p_filePath);
        users = new HashSet<>();
        dataSet = new ArrayList<>();
        owners = new ArrayList<>();
        accesses = new ArrayList<>();
        admin = new User("Luca", "Diavolo!");
        users.add(admin);
    }

    /*
    Verifica la condizione di IR
    @return true se IR = true; false altrimenti
     */
    private boolean repInv() {
        boolean ir;
        ir = users != null && dataSet != null && owners != null && accesses != null && admin != null &&
                admin.hasPassword() && users.contains(admin) && dataSet.size() == owners.size() && dataSet.size() == accesses.size() &&
                onlyUnique(dataSet);
        if (ir) {
            //For all map. map in accesses => map.keySet sottoinsieme di users
            for (Map<User, AccessLevel> map : accesses) {
                if (!users.containsAll(map.keySet())) {
                    ir = false;
                    break;
                }
            }
        }
        return ir;
    }

    /*
    Verifica se p_l contiene solo elementi unici (true); oppure no (false)
    @requires p_l != null
    @throws NullPointerException se p_l = null
    @return true p_l contiene almeno una coppia di elementi d1 e d2 per i quali d1.equals(d2); false altrimenti
     */
    private boolean onlyUnique(List<E> p_l) throws NullPointerException {
        if (p_l == null) throw new NullPointerException("p_l can't be null!");
        List<E> noDuplicates = new ArrayList<>(new HashSet<>(p_l)); //converto lista in un insieme. Di conseguenza possibile elementi duplicati vengono rimossi
        return p_l.size() == noDuplicates.size();
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
        if (passw == null) throw new NullPointerException("passw must be != null !");
        if (passw.isEmpty()) throw new IllegalArgumentException("passw can't be empty!");
        if (userExist(Id)) throw new DuplicatedUserException("users id must be unique !");

        users.add(new User(Id, passw));

        assert repInv();
    }

    /*
     Rimuove l’utente dalla collezione
     @requires Id != null && passw != null && !Id.isEmpty() && !passw.isEmpty() && !Id.equals(admin.id)
               (Exist u appartenente a U tale che u.id = Id && u.password = passw)
     @throws NullPointerException se Id = null || passw = null
     @throws IllegalArgumentException se Id.isEmpty() || passw.isEmpty() || Id.equals(admin.id)
     @throws CredentialException se Not (Exist u appartenente a U tale che u.id = Id && u.password = passw)
     @modifies this
     @effects u = {Id,passw} && this_post.U = this_pre.U - u &&
              this_post.D = this_pre.D - OwnedData(u)
     */
    @Override
    public void removeUser(String Id, String passw) throws NullPointerException, IllegalArgumentException, CredentialException {
        assert repInv();
        if (!userAuth(Id, passw)) throw new CredentialException("valid users' credentials are required !");
        if (Id.equals(admin.getId())) throw new IllegalArgumentException("admin user can't be removed !");

        User toRemove = new User(Id);

        //credenziali valide
        assert users.remove(toRemove); //rimuovo utente da insieme degli utenti presenti
        //L'insieme dei dati che prima appartenevano all'utente u con u.id = Id devono essere rimossi
        int lastOwner = owners.indexOf(toRemove);
        while (lastOwner != -1) {//Ci sono ancora dati di cui era proprietario da rimuovere
            owners.remove(lastOwner); //rimuovo proprietario del dato rimosso
            dataSet.remove(lastOwner); //rimuovo dato di cui era proprietario
            accesses.remove(lastOwner);  //rimuovo mappa deggli accessi definiti per il dato rimosso
            lastOwner = owners.indexOf(toRemove);
        }
        //Rimuovere eventuali accessi asseganti all'utente rimosso
        Iterator<Map<User, AccessLevel>> iterAccesses = accesses.iterator();
        while (iterAccesses.hasNext()) {
            Map<User, AccessLevel> map = iterAccesses.next();
            map.remove(toRemove);
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
        if (!userAuth(Owner, passw)) throw new CredentialException("valid users' credentials are required !");
        return Collections.frequency(owners, new User(Owner));
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
        if (!userAuth(Owner, passw)) throw new CredentialException("valid users' credentials are required !");
        if (file == null) throw new NullPointerException("file must be != null !");

        if (dataSet.contains(file)) return false;
        else {

            file = (E) deepCopy(file);
            dataSet.add(file);
            User usr = new User(Owner, passw);
            Map<User, AccessLevel> mapAcc = new HashMap<>();
            mapAcc.put(usr, AccessLevel.W);

            owners.add(usr);
            accesses.add(mapAcc);
        }

        assert repInv();
        return true;
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
    @return se file è presente restituisce una copia del file. La copia è una deep copy se l'utente ha accesso in sola lettura,
            mentre se ha accesso in scrittura viene restituito direttamente l'oggetto presente all'interno di this
    */
    @Override
    public E get(String Owner, String passw, E file) throws NullPointerException, IllegalArgumentException, CredentialException, NoAccessException {
        assert repInv();
        if (!userAuth(Owner, passw)) throw new CredentialException("valid users' credentials are required !");
        if (file == null) throw new NullPointerException("file must be != null !");
        int filePos = dataSet.indexOf(file);
        if (filePos == -1) throw new IllegalArgumentException("file must be inside data collection!");
        Map<User, AccessLevel> fileMapAcc = accesses.get(filePos);
        if (!fileMapAcc.containsKey(new User(Owner)))
            throw new NoAccessException("user " + Owner + " has no access to file");

        AccessLevel acc = fileMapAcc.get(new User(Owner)); //recupero livello di accesso associato all'utente

        readFileFromDisk(Owner, passw, file); //aggiornna file con contenuto del doc relativo

        assert repInv();
        return acc == AccessLevel.W ? dataSet.get(filePos) : (E) deepCopy(dataSet.get(filePos));
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
        if (!userAuth(Owner, passw)) throw new CredentialException("valid users' credentials are required !");
        if (file == null) throw new NullPointerException("file must be != null !");
        int filePos = dataSet.indexOf(file);
        if (filePos == -1) throw new IllegalArgumentException("file must be inside data collection!");
        if (!owners.get(filePos).equals(new User(Owner)))
            throw new NoAccessException("user " + Owner + " must be the Owner to remove file!");

        E res = dataSet.remove(filePos);
        owners.remove(filePos);
        accesses.remove(filePos);

        if (!new File(res.getFilePath()).delete()) System.out.println("Failed to remove file: " + res.getFilePath());

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
    @effects effettua una copia di file con nuovo file path
     */
    @Override
    public void copy(String Owner, String passw, E file, String newFilePath) throws NullPointerException, IllegalArgumentException, CredentialException, NoAccessException {
        assert repInv();
        if (!userAuth(Owner, passw)) throw new CredentialException("valid users' credentials are required !");
        if (file == null) throw new NullPointerException("file must be != null !");
        int filePos = dataSet.indexOf(file);
        if (filePos == -1) throw new IllegalArgumentException("file must be inside data collection!");
        if (!owners.get(filePos).equals(new User(Owner)))
            throw new NoAccessException("user " + Owner + " must be the Owner to copy file!");
        if (dataSet.contains(new SecureFile(newFilePath)))
            throw new IllegalArgumentException("newfilePath must be unique inside data collection!");

        put(Owner, passw, (E) new SecureFile(newFilePath));

        assert repInv();
    }

    /*
    Condivide in lettura il file nella collezione con un altro utente
    se vengono rispettati i controlli di identità
    @requires Owner != null && passw != null && Other!=null && Owner != Other && !Owner.isEmpty() && !passw.isEmpty() && !Other.isEmpty()
              && file != null &&
              (Exist u appartenente a U tale che u.id = Owner && u.password = passw && OwnedData(u) contiene file) &&
              (Exist u appartenente a U tale che u.id = Other)
    @throws NullPointerException se Owner = null || passw = null || Other = null || file = null
    @throws IllegalArgumentException se Owner.isEmpty() || passw.isEmpty() || Other.isEmpty() || Owner = Other
    @throws CredentialException se Not (Exist u appartenente a U tale che u.id = Owner && u.password = passw)
    @throws UnknownUserException Not (Exist u appartenente a U tale che u.id = Other)
    @throws NoAccessException se (Exist u appartenente a U tale che u.id = Owner && u.password = passw) &&
            Not (Exist u appartenente a U tale che u.id = Owner && u.password = passw && OwnedData(u) contiene file)
    @modifies this
    @effects u= {Other, passw}, Access(u,file) = r
     */
    @Override
    public void shareR(String Owner, String passw, String Other, E file) throws NullPointerException, IllegalArgumentException, CredentialException, UnknownUserException, NoAccessException {
        setAccesses(Owner, passw, Other, file, AccessLevel.R);
    }

    /*
    Condivide in lettura e scrittura il file nella collezione con un altro utente
    se vengono rispettati i controlli di identità
    @requires Owner != null && passw != null && Other!=null && Owner != Other && !Owner.isEmpty() && !passw.isEmpty() && !Other.isEmpty()
              && file != null &&
              (Exist u appartenente a U tale che u.id = Owner && u.password = passw && OwnedData(u) contiene file) &&
              (Exist u appartenente a U tale che u.id = Other)
    @throws NullPointerException se Owner = null || passw = null || Other = null || file = null
    @throws IllegalArgumentException se Owner.isEmpty() || passw.isEmpty() || Other.isEmpty() || Owner = Other
    @throws CredentialException se Not (Exist u appartenente a U tale che u.id = Owner && u.password = passw)
    @throws UnknownUserException Not (Exist u appartenente a U tale che u.id = Other)
    @throws NoAccessException se (Exist u appartenente a U tale che u.id = Owner && u.password = passw) &&
            Not (Exist u appartenente a U tale che u.id = Owner && u.password = passw && OwnedData(u) contiene file)
    @modifies this
    @effects u= {Other, passw}, Access(u,file) = w
    */
    @Override
    public void shareW(String Owner, String passw, String Other, E file) throws NullPointerException, IllegalArgumentException, CredentialException, UnknownUserException, NoAccessException {
        setAccesses(Owner, passw, Other, file, AccessLevel.W);
    }

    /*
    Assegna livello di accesso a file nella collezione ad un utente Other se le credenziali Owner e passw identificano
    correttamente il proprietario di file.
    @requires Owner != null && passw != null && Other!=null && Owner != Other && !Owner.isEmpty() && !passw.isEmpty() && !Other.isEmpty()
              && file != null && acc != null &&
              (Exist u appartenente a U tale che u.id = Owner && u.password = passw && OwnedData(u) contiene file) &&
              (Exist u appartenente a U tale che u.id = Other)
    @throws NullPointerException se Owner = null || passw = null || Other = null || file = null
    @throws IllegalArgumentException se Owner.isEmpty() || passw.isEmpty() || Other.isEmpty() || Owner = Other || acc = null
    @throws CredentialException se Not (Exist u appartenente a U tale che u.id = Owner && u.password = passw)
    @throws UnknownUserException Not (Exist u appartenente a U tale che u.id = Other)
    @throws NoAccessException se (Exist u appartenente a U tale che u.id = Owner && u.password = passw) &&
            Not (Exist u appartenente a U tale che u.id = Owner && u.password = passw && OwnedData(u) contiene file)
    @modifies this
    @effects u= {Other, passw}, Access(u,file) = w
     */
    private void setAccesses(String Owner, String passw, String Other, E file, AccessLevel acc) throws NullPointerException, IllegalArgumentException, CredentialException, UnknownUserException, NoAccessException {
        assert repInv();
        if (!userAuth(Owner, passw)) throw new CredentialException("valid users' credentials are required !");
        if (Other == null) throw new NullPointerException("Other must be != null !");
        if (acc == null) throw new IllegalArgumentException("acc can't be null !");
        if (Other.isEmpty()) throw new IllegalArgumentException("Other can't be empty!");
        if (Owner.equals(Other)) throw new IllegalArgumentException("You can't share data with yourself!");
        if (file == null) throw new NullPointerException("file must be != null !");
        int filePos = dataSet.indexOf(file);
        if (filePos == -1) throw new IllegalArgumentException("file must be inside data collection!");
        if (!owners.get(filePos).equals(new User(Owner)))
            throw new NoAccessException("user " + Owner + " must be the Owner to share file!");
        if (!users.contains(new User(Other)))
            throw new UnknownUserException("you are trying to share a file with unknown user: " + Other);

        User otherUser = getUser(Other);
        accesses.get(filePos).put(otherUser, acc);

        assert repInv();
    }

    private class UserFilesIterator implements Iterator<E> {
        private E current; //elemento corrente
        private User targetUser; //proprietario dei file
        private int currentTargetPos = -1; //Ultima posizione di targetUser in owners

        //Inizializza putatore al primo dato di cui è proprietario targetUser
        UserFilesIterator(User p_targetUser){
            targetUser = p_targetUser;
            currentTargetPos = ListSecureDataContainer.this.owners.indexOf(p_targetUser);
            current = currentTargetPos == -1 ? null : ListSecureDataContainer.this.dataSet.get(currentTargetPos);
        }

        /*
         * Verifica se sono rimasti ancora dei dati da visitare
         * @return ci sono ancora dati da visitare; false altrimenti
         */
        @Override
        public boolean hasNext() {
            return current == null;
        }

        /*
         * Restituisce dato corrente di targetUser e aggiorna il puntatore.
         * @modifies current
         * @effect current punta al successivo dato da visitare; se non ce ne sono altri current = null
         * @return dato corrente di targetUser
         */
        @Override
        public E next() {
            E data = current;
            //Recupero posizione (se possibile) di un altra occorrenza di targetUser nella lista dei proprietari rimanente
            int newTargetPos = ListSecureDataContainer.this.owners.subList(currentTargetPos+1,owners.size()).indexOf(targetUser);
            //Se non trovo altre occorrenze nella lista rimanente significa che ho finito la visita; altrimenti assegno a currentTargetPos
            //la posizione della nuova occorrenza trovata nella lista rimanente.
            currentTargetPos = newTargetPos == -1 ? -1 : currentTargetPos + 1 + newTargetPos;
            current = currentTargetPos == -1 ? null : ListSecureDataContainer.this.dataSet.get(currentTargetPos);
            return  data;
        }

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
        assert repInv();
        if (!userAuth(Owner, passw)) throw new CredentialException("valid users' credentials are required !");
        //Restituisco Iteratore senza remove dei file di cui Owner è il proprietario
        return new UserFilesIterator(new User(Owner));
    }

    /*
    Memorizza file nel documento su disco relativo
    @requires Id != null && passw != null && !Id.isEmpty() && !passw.isEmpty() && file != null &&
              (Exist (u,d) appartenente a U tale che u.id = Id && u.password = passw && d = file && Access(u,d) = w)
    @throws NullPointerException se Id = null || passw = null || file = null
    @throws IllegalArgumentException se Id.isEmpty() || passw.isEmpty()
    @throws CredentialException se Not (Exist u appartenente a U tale che u.id = Id && u.password = passw)
    @throws NoAccessException se (Exist u appartenente a U tale che u.id = Id && u.password = passw) &&
            Not (Exist (u,d) appartenente a U tale che u.id = Id && u.password = passw && d = file && Access(u,d) = w)
    @effects scrivi contenuto di file nel documento su disco relativo
    @return restitusice true se la scrittura è andata a buon fine; false altrimenti
     */
    @Override
    public boolean writeFileOnDisk(String Id, String passw, E file) throws NullPointerException, IllegalArgumentException, CredentialException, NoAccessException {
        assert repInv();
        if (!userAuth(Id, passw)) throw new CredentialException("valid users' credentials are required !");
        if (file == null) throw new NullPointerException("file must be != null !");
        int filePos = dataSet.indexOf(file);
        if (filePos == -1) throw new IllegalArgumentException("file must be inside data collection!");
        if (!accesses.get(filePos).containsKey(new User(Id)))
            throw new NoAccessException("user " + Id + " has no access to file");
        if (accesses.get(filePos).get(new User(Id)) != AccessLevel.W)
            throw new NoAccessException("user " + Id + " must have write access to file!");
        // Serialization
        try {
            //Salvo oggetto file nel documento su disco relativo

            E containerFile = dataSet.get(filePos); //recupero file da container
            FileOutputStream f = new FileOutputStream(containerFile.getFilePath());
            ObjectOutputStream out = new ObjectOutputStream(f);

            out.writeObject(containerFile); //memorizzo contenuto di containerFile su disco

            out.close();
            f.close();

            System.out.println("Object has been serialized");
        } catch (IOException ex) {
            ex.printStackTrace();
            return false;
        }
        assert repInv();
        return true;
    }

    /*
    Leggi file dal documento su disco relativo
    @requires Id != null && passw != null && !Id.isEmpty() && !passw.isEmpty() && file != null &&
              (Exist (u,d) appartenente a U tale che u.id = Id && u.password = passw && d = file && Access(u,d) = w)
    @throws NullPointerException se Id = null || passw = null || file = null
    @throws IllegalArgumentException se Id.isEmpty() || passw.isEmpty()
    @throws CredentialException se Not (Exist u appartenente a U tale che u.id = Id && u.password = passw)
    @throws NoAccessException se (Exist u appartenente a U tale che u.id = Id && u.password = passw) &&
            Not (Exist (u,d) appartenente a U tale che u.id = Id && u.password = passw && d = file && Access(u,d) = w)
    @modifies this
    @effects recupera contenuto di file da documento su disco relativo
    */
    @Override
    public boolean readFileFromDisk(String Id, String passw, E file) throws NullPointerException, IllegalArgumentException, CredentialException, NoAccessException {
        assert repInv();
        if (!userAuth(Id, passw)) throw new CredentialException("valid users' credentials are required !");
        if (file == null) throw new NullPointerException("file must be != null !");
        int filePos = dataSet.indexOf(file);
        if (filePos == -1) throw new IllegalArgumentException("file must be inside data collection!");
        if (!accesses.get(filePos).containsKey(new User(Id)))
            throw new NoAccessException("user " + Id + " has no access to file");

        // Deserialization
        try {
            FileInputStream f = new FileInputStream(file.getFilePath());
            ObjectInputStream in = new ObjectInputStream(f);

            E newfile = (E) in.readObject();
            //Rimuovo vecchio file da container e metto quello appena letto da documento
            dataSet.set(filePos, newfile);

            in.close();
            f.close();

            System.out.println("Object has been deserialized");
        } catch (IOException | ClassNotFoundException ex) {
            ex.printStackTrace();
            return false;
        }

        assert repInv();
        return true;
    }

    /*
    Inizializza this con ciò che viene letto dal documento su disco relativo
    @requires Id != null && passw != null && !Id.isEmpty() && !passw.isEmpty() &&
              (Exist (u,d) appartenente a U tale che u.id = Id && u.password = passw && id = admin.id)
    @throws NullPointerException se Id = null || passw = null || file = null
    @throws IllegalArgumentException se Id.isEmpty() || passw.isEmpty()
    @throws CredentialException se Not (Exist u appartenente a U tale che u.id = Id && u.password = passw && id = admin.id)
    @throws IOException se si verifica un problema durante la scrittura su file
    @modifies this
    @effects inizializza this con ciò che viene letto dal documento su disco relativo
    @return restituisce true se la lettura ha successo; false altrimenti
     */
    @Override
    public boolean readContainerFromDisk(String Id, String passw) throws NullPointerException, IllegalArgumentException, CredentialException {
        assert repInv();
        if (!userAuth(Id, passw)) throw new CredentialException("valid users' credentials are required !");
        if (!admin.equals(new User(Id))) throw new CredentialException("user " + Id + " is not an admin");
        // Deserialization
        try {
            FileInputStream f = new FileInputStream(getFilePath()); //doc sul quale effettuare la lettura
            ObjectInputStream in = new ObjectInputStream(f);

            ListSecureDataContainer<E> newContainer = (ListSecureDataContainer<E>) in.readObject();
            //Aggiorno variabili di istanza
            this.admin = newContainer.admin;
            this.users = newContainer.users;
            this.dataSet = newContainer.dataSet;
            this.owners = newContainer.owners;
            this.accesses = newContainer.accesses;

            in.close();
            f.close();
        } catch (IOException | ClassNotFoundException ex) {
            ex.printStackTrace();
            return false;
        }
        assert repInv();
        return true;
    }

    /*
    Memorizza this nel documento su disco relativo
    @requires Id != null && passw != null && !Id.isEmpty() && !passw.isEmpty() &&
              (Exist (u,d) appartenente a U tale che u.id = Id && u.password = passw && id = admin.id)
    @throws NullPointerException se Id = null || passw = null || file = null
    @throws IllegalArgumentException se Id.isEmpty() || passw.isEmpty()
    @throws CredentialException se Not (Exist u appartenente a U tale che u.id = Id && u.password = passw && id = admin.id)
    @effects scrivi contenuto di this nel documento su disco relativo
    @return restituisce true se this viene scritto correttamente su disco; false atrimenti
     */
    @Override
    public boolean writeContainerOnDisk(String Id, String passw) throws NullPointerException, IllegalArgumentException, CredentialException {
        assert repInv();
        if (!userAuth(Id, passw)) throw new CredentialException("valid users' credentials are required !");
        if (!admin.equals(new User(Id))) throw new CredentialException("user " + Id + " is not an admin");
        // Serialization
        try {
            FileOutputStream f = new FileOutputStream(getFilePath()); //doc sul quale effettuare la scrittura
            ObjectOutputStream out = new ObjectOutputStream(f);

            out.writeObject(this); //memorizzo contenuto del container su disco

            out.close();
            f.close();
        } catch (IOException ex) {
            ex.printStackTrace();
            return false;
        }
        assert repInv();
        return true;
    }

    /*
    Verifica se esiste un utente u con u.id = id
    @requires Id != null && !Id.isEmpty()
    @throws NullPointerException se Id = null || passw = null
    @throws IllegalArgumentException se Id.isEmpty()
    @return true se esiste un utente u tale che u.id = Id; false altrimenti
    */
    @Override
    public boolean userExist(String Id) throws NullPointerException, IllegalArgumentException {
        assert repInv();
        if (Id == null) throw new NullPointerException("Id must be != null !");
        if (Id.isEmpty()) throw new IllegalArgumentException("Id can't be empty!");
        assert repInv();
        return users.contains(new User(Id));
    }

    /*
    Verifica se esiste un utente u con u.id = id e u.password = passw
    @requires Id != null && passw != null && !Id.isEmpty() && !passw.isEmpty()
    @throws NullPointerException se Id = null || passw = null
    @throws IllegalArgumentException se Id.isEmpty() || passw.isEmpty()
    @return true se esiste un utente u tale che u.id = Id && u.password = passw; false altrimenti
    */
    @Override
    public boolean userAuth(String Id, String passw) throws NullPointerException, IllegalArgumentException {
        assert repInv();
        if (Id == null) throw new NullPointerException("Id must be != null !");
        if (Id.isEmpty()) throw new IllegalArgumentException("Id can't be empty!");
        if (passw == null) throw new NullPointerException("passw must be != null !");
        if (passw.isEmpty()) throw new IllegalArgumentException("passw can't be empty!");
        for (User u : users) {
            if (u.equals(new User(Id)) && u.auth(passw)) return true;
        }
        assert repInv();
        return false;
    }

    private User getUser(String Id) {
        assert repInv();
        Iterator<User> iterUsers = users.iterator();
        User res = null;
        User target = new User(Id);
        while (iterUsers.hasNext()) {
            res = iterUsers.next();
            if (res.equals(target)) break;
        }
        assert repInv();
        return res;
    }

    /* Restituisce una deep copy di orig, o null se l'oggetto non può essere serializzato.
     * @requires orig != null
     * @throws NullPointerException se orig = null
     * @return null se si è verificato
     */
    private Object deepCopy(Object orig) throws NullPointerException {
        if (orig == null) throw new NullPointerException("orig ucan't be null!");

        Object obj = null;
        try {
            // Conversione dell'oggetto in un array di byte
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            ObjectOutputStream out = new ObjectOutputStream(bos);
            out.writeObject(orig);
            out.flush();
            out.close();

            // Crea un input stream dall'array di byte e leggi
            // una copia dell'oggetto
            ObjectInputStream in = new ObjectInputStream(
                    new ByteArrayInputStream(bos.toByteArray()));
            obj = in.readObject();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (ClassNotFoundException cnfe) {
            cnfe.printStackTrace();
        }
        return obj;
    }
}
