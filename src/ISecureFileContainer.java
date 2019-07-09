import Exceptions.CredentialException;
import Exceptions.DuplicatedUserException;
import Exceptions.NoAccessException;
import Exceptions.UnknownUserException;

import java.util.Iterator;

public interface ISecureFileContainer<E>  {
    /*
     * Overview:
     * ISecureFileContainer<E> è  un  contenitore  di oggetti  di  tipo  E.  Intuitivamente  la collezione  si  comporta
     * come una specie File Storage per la memorizzazione e condivisione di file. La collezione deve garantire un
     * meccanismo di sicurezza dei  file fornendo un proprio  meccanismo di  gestione delle identità degli utenti.
     * Ogni file  ha  un  proprietario  che ha  diritto  a  leggere,  scrivere  e fare  una  copia. La  collezione
     * deve,  inoltre, fornire un meccanismo di controllo degli accessi che permette al proprietario del file di
     * eseguire una restrizione  selettiva  dell'accesso  ai  suoi  file inseriti  nella  collezione.  Alcuni  utenti
     * possono  essere  autorizzatidal proprietario ad accedere ai suoi file (in solo lettura o anche scrittura) mentre
     * altri non possono accedervi  senza  autorizzazione. Ma  l’utente  deve  accettare  la  condivisione previa
     * autenticazione.
     *
     *  Typical Element:
     *  Un tipico ISecureFileContainer<E> è costituito dai seguenti elementi:
     *      U = {u0,u1,...,un-1} è un insieme di n utenti.
     *          ui = {id, password}
     *
     *      D = {d0,d1,...,dm-1} è un insieme di m elementi di tipo E.
     *
     *      A = {r,w,u} insieme dei livelli di accesso ai dati:
     *         - u: undefined
     *         - r: read
     *         - w: write
     *
     *      Owner: D -> U
     *         E' una funzione totale che associa a ciascun elemento d di D un elemento di U.
     *         Dati u di U, d di D Owner(d) = u ha il seguente significato:
     *         Il proprietario di d è l'utente u
     *
     *      Access: D * U -> A
     *         E' una funzione totale che associa ad ogni coppia (u,d) di D * U un elemento di A.
     *         Dati u di U, d di D, a di A Access(u,d) = a ha il seguente significato:
     *         L'utente u ha un livello di accesso pari ad a nei confronti del dato d.
     *
     * Vincoli e proprietà:
     *
     *      - Il proprietario u di un dato d ha accesso in lettura e scrittura a d:
     *        For all d di D. Owner(d) = u => Access(u,d) = w
     *      - Insieme dei dati posseduti da un utente u: OwnedData(u) = {d di D| Owner(d) = u}
     *
     */

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
    void createUser(String Id, String passw) throws NullPointerException, IllegalArgumentException,
            DuplicatedUserException;

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
    int getSize(String Owner, String passw) throws NullPointerException, IllegalArgumentException, CredentialException;

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
    boolean put(String Owner, String passw, E file) throws NullPointerException, IllegalArgumentException,
                                                           CredentialException;

    /*
    Ottiene una copia del file nella collezione
    se vengono rispettati i controlli di identità
    @requires Owner != null && passw != null && !Owner.isEmpty() && !passw.isEmpty() && file != null &&
              (Exist (u,d) appartenente a (D * U) tale che u.id = Id && u.password = passw &&
              (Access((u,d)) = w || Access((u,d)) = r) )
    @throws NullPointerException se Id = null || passw = null || file = null || file non in D
    @throws IllegalArgumentException se Owner.isEmpty() || passw.isEmpty()
    @throws CredentialException se Not (Exist u appartenente a U tale che u.id = Id && u.password = passw)
    @throws NoAccessException se (Exist u appartenente a U tale che u.id = Owner && u.password = passw) &&
                                 Not (Exist (u,d) appartenente a (D * U) tale che u.id = Id && u.password = passw &&
                                      (Access((u,d)) = w || Access((u,d)) = r) )
    @return restituisce una copia del file
    */
    E get(String Owner, String passw, E file) throws NullPointerException, IllegalArgumentException,
            CredentialException, NoAccessException;

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
    E remove(String Owner, String passw, E file) throws NullPointerException, IllegalArgumentException,
                                                        CredentialException, NoAccessException;

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
    void copy(String Owner, String passw, E file, String newFilePath) throws NullPointerException, IllegalArgumentException,
                                                         CredentialException, NoAccessException;

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
    void shareR(String Owner, String passw, String Other, E file) throws NullPointerException, IllegalArgumentException,
                                                                         CredentialException, UnknownUserException,
                                                                         NoAccessException;

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
    void shareW(String Owner, String passw, String Other, E file) throws NullPointerException, IllegalArgumentException,
                                                                         CredentialException, UnknownUserException,
                                                                         NoAccessException;

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
    Iterator<E> getIterator(String Owner, String passw) throws NullPointerException, IllegalArgumentException,
                                                               CredentialException;

    // ****** ...altre operazione da definire a scelta *******

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
    void removeUser(String Id, String passw) throws NullPointerException, IllegalArgumentException, CredentialException;

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
    boolean writeFileOnDisk(String Id, String passw, E file) throws NullPointerException, IllegalArgumentException,
                                                           CredentialException, NoAccessException;

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
    boolean readFileFromDisk(String Id, String passw, E file) throws NullPointerException, IllegalArgumentException,
            CredentialException, NoAccessException;

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
    boolean readContainerFromDisk(String Id, String passw) throws NullPointerException, IllegalArgumentException, CredentialException;

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
    boolean writeContainerOnDisk(String Id, String passw) throws NullPointerException, IllegalArgumentException, CredentialException;

    /*
    Verifica se esiste un utente u con u.id = id
    @requires Id != null && !Id.isEmpty()
    @throws NullPointerException se Id = null || passw = null
    @throws IllegalArgumentException se Id.isEmpty()
    @return true se esiste un utente u tale che u.id = Id; false altrimenti
    */
    boolean userExist(String Id) throws NullPointerException, IllegalArgumentException;

    /*
    Verifica se esiste un utente u con u.id = id e u.password = passw
    @requires Id != null && passw != null && !Id.isEmpty() && !passw.isEmpty()
    @throws NullPointerException se Id = null || passw = null
    @throws IllegalArgumentException se Id.isEmpty() || passw.isEmpty()
    @return true se esiste un utente u tale che u.id = Id && u.password = passw; false altrimenti
    */
    boolean userAuth(String Id, String passw) throws NullPointerException, IllegalArgumentException;
}
