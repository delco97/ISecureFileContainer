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

    ListSecureDataContainer(String p_filePath) throws NullPointerException, IllegalArgumentException {
        super(p_filePath);
        dataSet = new ArrayList<>();
        owners = new ArrayList<>();
        accesses = new ArrayList<>();
        admin = new User("Luca", "Diavolo!");
        users.add(admin);
    }

    @Override
    public void createUser(String Id, String passw) throws NullPointerException, IllegalArgumentException, DuplicatedUserException {

    }

    @Override
    public int getSize(String Owner, String passw) throws NullPointerException, IllegalArgumentException, CredentialException {
        return 0;
    }

    @Override
    public boolean put(String Owner, String passw, E file) throws NullPointerException, IllegalArgumentException, CredentialException {
        return false;
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
    public void copy(String Owner, String passw, E file, String newFilePath) throws NullPointerException, IllegalArgumentException, CredentialException, NoAccessException {

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
    public void removeUser(String Id, String passw) throws NullPointerException, IllegalArgumentException, CredentialException {

    }

    @Override
    public boolean writeFileOnDisk(String Id, String passw, E file) throws NullPointerException, IllegalArgumentException, CredentialException, NoAccessException {
        return false;
    }

    @Override
    public boolean readFileFromDisk(String Id, String passw, E file) throws NullPointerException, IllegalArgumentException, CredentialException, NoAccessException {
        return false;
    }

    @Override
    public boolean readContainerFromDisk(String Id, String passw) throws NullPointerException, IllegalArgumentException, CredentialException {
        return false;
    }

    @Override
    public boolean writeContainerOnDisk(String Id, String passw) throws NullPointerException, IllegalArgumentException, CredentialException {
        return false;
    }

    @Override
    public boolean userExist(String Id) throws NullPointerException, IllegalArgumentException {
        return false;
    }

    @Override
    public boolean userAuth(String Id, String passw) throws NullPointerException, IllegalArgumentException {
        return false;
    }
}
