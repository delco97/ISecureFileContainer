public class IllegalInvocationException extends RuntimeException {

    /**
     * Costruttore per CredentialException senza dettagli.
     */
    public IllegalInvocationException() {
        super();
    }

    /**
     * Costruttore per CredentialException con dettagli.
     */
    public IllegalInvocationException(String msg) {
        super(msg);
    }
}