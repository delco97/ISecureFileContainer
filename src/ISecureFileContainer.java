import java.io.Serializable;
import java.util.Iterator;

public interface ISecureFileContainer<E extends SecureFile > {
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
     *      U = {u0,u1,...,un-1} è un insieme di n utenti
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
     *      Access: U * D -> A
     *         E' una funzione totale che associa ad alcune coppie (u,d) di U * D un elemento di A.
     *         Dati u di U, d di D, a di A Access(u,d) = a ha il seguente significato:
     *         L'utente u ha un livello di accesso pari ad a nei confronti del dato d.
     *
     * Vincoli e proprietà:
     *
     *      - Il proprietario u di un dato d ha accesso in lettura e scrittura a d:
     *        For all d di D. Owner(d) = u => Access(u,d) = w
     *
     *
     */

    // Crea l’identità di un nuovo utente della collezione
    void createUser(String Id, String passw);

    // Restituisce il numero dei file di un utente presenti nella
    // collezione
    int getSize(String Owner, String passw);

    // Inserisce il il file nella collezione
    // se vengono rispettati i controlli di identità
    boolean put(String Owner, String passw, E file);

    // Ottiene una copia del file nella collezione
    // se vengono rispettati i controlli di identità
    E get(String Owner, String passw, E file);

    // Rimuove il file dalla collezione
    // se vengono rispettati i controlli di identità
    E remove(String Owner, String passw, E file);

    // Crea una copia del file nella collezione
    // se vengono rispettati i controlli di identità
    void copy(String Owner, String passw, E file);

    // Condivide in lettura il file nella collezione con un altro utente
    // se vengono rispettati i controlli di identità
    void shareR(String Owner, String passw, String Other, E file);

    // Condivide in lettura e scrittura il file nella collezione con un altro
    // utente se vengono rispettati i controlli di identità
    void shareW(String Owner, String passw, String Other, E file);

    // restituisce un iteratore (senza remove) che genera tutti i file
    //dell’utente in ordine arbitrario
    // se vengono rispettati i controlli di identità
    Iterator<E> getIterator(String Owner, String passw);

    // … altre operazione da definire a scelta
}
