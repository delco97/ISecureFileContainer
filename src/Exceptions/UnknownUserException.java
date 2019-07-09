package Exceptions;

public class UnknownUserException extends RuntimeException{
    /**
     * Costruttore per UnknownUserException senza dettagli.
     */
    public UnknownUserException() {
        super();
    }

    /**
     * Costruttore per UnknownUserException con dettagli.
     */
    public UnknownUserException(String msg) {
        super(msg);
    }
}
