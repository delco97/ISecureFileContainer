import java.io.Serializable;
import java.util.Objects;

public class SecureFile implements Serializable{
    /*
     * Overview:
     * SecureFile è un oggetto che può essere inserito all'interno di ISecureFileContainer.
     *
     * Typical Element:
     *    - filePath: indirizzo del file nel quale viene memorizzato l'oggetto
     */

    private static final long serialversionUID = 129348938L;
    private String filePath;

    /*
    Costruttore
    @requires p_filePath != null && !p_filePath.isEmpty()
    @throws NullPointerException se p_filePath == null
    @throws IllegalArgumentException se p_filePath.isEmpty()
     */
    SecureFile(String p_filePath) throws NullPointerException, IllegalArgumentException{
        setFilePath(p_filePath);
    }
    /*
    Costruttore di copia
    @requires p_sFile.p_filePath != null && !p_sFile.p_filePath.isEmpty()
    @throws NullPointerException se p_sFile == null
    @throws IllegalArgumentException se p_filePath.isEmpty()
     */
    SecureFile(SecureFile p_sFile) throws NullPointerException, IllegalArgumentException{
        this(p_sFile.getFilePath());
    }

    /*
    Modifica filePath
    @requires p_filePath != null && !p_filePath.isEmpty()
    @throws NullPointerException se p_filePath == null
    @throws IllegalArgumentException se p_filePath.isEmpty()
     */
    public void setFilePath(String p_filePath)throws NullPointerException, IllegalArgumentException{
        if(p_filePath == null) throw new NullPointerException("p_filePath must be != null !");
        if(p_filePath.isEmpty()) throw new IllegalArgumentException("p_filePath can't be an empty string!");
        //TODO: Check if p_filePath is a valid file path
        this.filePath = p_filePath;
    }

    public String getFilePath() {
        return filePath;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        SecureFile that = (SecureFile) o;
        return filePath.equals(that.filePath);
    }

    @Override
    public int hashCode() {
        return Objects.hash(filePath);
    }
}
