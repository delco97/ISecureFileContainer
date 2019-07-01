public class NoAccessException extends RuntimeException {
    /**
     * Costruttore per NoAccessException senza dettagli.
     */
    public NoAccessException() {
        super();
    }

    /**
     * Costruttore per NoAccessException con dettagli.
     */
    public NoAccessException(String msg) {
        super(msg);
    }
}
