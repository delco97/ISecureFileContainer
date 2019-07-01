
public class DuplicatedUserException extends RuntimeException{
    /**
     * Costruttore per DuplicatedUserException senza dettagli.
     */
    public DuplicatedUserException() {
        super();
    }

    /**
     * Costruttore per DuplicatedUserException con dettagli.
     */
    public DuplicatedUserException(String msg) {
        super(msg);
    }
}
