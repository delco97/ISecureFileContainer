package Exceptions;

public class IllegalInvocationException extends RuntimeException {

    /**
     * Costruttore per IllegalInvocationException senza dettagli.
     */
    public IllegalInvocationException() {
        super();
    }

    /**
     * Costruttore per IllegalInvocationException con dettagli.
     */
    public IllegalInvocationException(String msg) {
        super(msg);
    }
}