import java.util.Iterator;

public interface ISecureFileContainer<E> {
    /*
     * Overview:
     * ISecureFileContainer<E> è  un  contenitore  di oggetti  di  tipo  E.  Intuitivamente  la collezione  si  comporta  come
     * una specie File Storage per la memorizzazione e condivisione di file. La collezione deve garantire un
     * meccanismo di sicurezza dei  file fornendo un proprio  meccanismo di  gestione delle identità degli utenti.
     * Ogni file  ha  un  proprietario  che ha  diritto  a  leggere,  scrivere  e fare  una  copia. La  collezione  deve,  inoltre,
     * fornire un meccanismo di controllo degli accessi che permette al proprietario del file di eseguire una
     * restrizione  selettiva  dell'accesso  ai  suoi  file inseriti  nella  collezione.  Alcuni  utenti  possono  essere  autorizzati
     * dal proprietario ad accedere ai suoi file (in solo lettura o anche scrittura) mentre altri non possono
     * accedervi  senza  autorizzazione. Ma  l’utente  deve  accettare  la  condivisione previa  autenticazione.
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
