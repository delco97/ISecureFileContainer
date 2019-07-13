package SecureContainer.Exceptions;

public class CredentialException extends RuntimeException {

    /**
     * Costruttore per CredentialException senza dettagli.
     */
    public CredentialException() {
        super();
    }

    /**
     * Costruttore per CredentialException con dettagli.
     */
    public CredentialException(String msg) {
        super(msg);
    }
}