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

    //Perché è opportuno definire serialversionUID ?
    // -> https://stackoverflow.com/questions/285793/what-is-a-serialversionuid-and-why-should-i-use-it
    private static final long serialversionUID = 20L;
    private String filePath; //file path assoluto del file sul quale this può essere scritto/letto

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
    Modifica filePath
    @requires p_filePath != null && !p_filePath.isEmpty()
    @throws NullPointerException se p_filePath == null
    @throws IllegalArgumentException se p_filePath.isEmpty()
    @modifies this
    @effect Modifica filePath
     */
    private void setFilePath(String p_filePath)throws NullPointerException, IllegalArgumentException{
        if(p_filePath == null) throw new NullPointerException("p_filePath must be != null !");
        if(p_filePath.isEmpty()) throw new IllegalArgumentException("p_filePath can't be an empty string!");
        //TODO: Check if p_filePath is a valid file path
        this.filePath = p_filePath;
    }

    /*
    Restituisce filePath
    @effect Restituisce filePath
     */
    public String getFilePath() {
        return filePath;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null) return false;
        try {
            SecureFile that = (SecureFile) o;
            return filePath.equals(that.filePath);
        }catch (ClassCastException e){
            return false;
        }
    }

    @Override
    public int hashCode() {
        return Objects.hash(filePath);
    }

//    @Override
//    public boolean equals(Object o) {
//        if (this == o || o == null) return true;
//        SecureFile that = (SecureFile) o;
//        return filePath.equals(that.filePath);
//    }

}
