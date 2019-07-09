import Exceptions.CredentialException;
import Exceptions.DuplicatedUserException;
import Exceptions.NoAccessException;
import Exceptions.UnknownUserException;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import javax.swing.filechooser.FileSystemView;
import java.io.File;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

class Exam_SecureWrap extends SecureFile{
    public String name;
    public int grade;

    Exam_SecureWrap(String p_filePath) throws NullPointerException, IllegalArgumentException {
        super(p_filePath);
    }

    Exam_SecureWrap(String p_filePath, String p_name, int p_grade) throws NullPointerException, IllegalArgumentException {
        super(p_filePath);
        name = p_name;
        grade = p_grade;
    }

}

class ISecureFileContainerTest {
    private static String testFolderPath; //path della cartella di test relativo alla home dell'utente corrente
    private static Path testFolder;
    private static ISecureFileContainer<Exam_SecureWrap> data;

    /*
    Elimina cartella folder e il suo contenuto
     */
    static void deleteFolder(File folder) {
        File[] files = folder.listFiles();
        if(files!=null) { //Alemo un file presente nella cartella
            for(File f: files) {
                if(f.isDirectory()) {
                    deleteFolder(f);
                } else {
                    f.delete();
                }
            }
        }
        folder.delete();
    }

    @BeforeAll
    /*
    Preparazione per l'esecuzione della batteria di test
     */
    static void init(){
        System.out.println("Preparazione pre-test");
        //Cancello cartella di test se presente
        testFolder = Paths.get(FileSystemView.getFileSystemView()
                        .getHomeDirectory()
                        .getAbsolutePath(),
                "Desktop/SecureFileContainer_test"); //path cartella di test

        testFolderPath = testFolder.toString();
        deleteFolder(testFolder.toFile()); //cancella cartella precedente, se presente
        assertTrue(testFolder.toFile().mkdirs(), "Il test non può essere effettuato_" +
                " se non è possibile creare la cartella di test: " + testFolder); //Crea nuova cartella di test
    }

    static void createContainer(int p_implementation){
        switch ( p_implementation){
            case 1:
                data = new MapSecureDataContainer<>(testFolderPath + "/container1_dump.ser");
                break;
            case 2:
                //TODO: crea nuova implementazione
                data = new ListSecureDataContainer<>(testFolderPath + "/container2_dump.ser");
                break;
            default:
                throw new IllegalArgumentException(p_implementation + "doesn't identify an implementation");
        }
    }

    @BeforeEach
    void cleanTestFolder() {
        deleteFolder(testFolder.toFile()); //cancella cartella precedente, se presente
        assertTrue(testFolder.toFile().mkdirs(), "Il test non può essere effettuato_" +
                " se non è possibile creare la cartella di test: " + testFolder); //Crea nuova cartella di test
    }

    @ParameterizedTest
    @ValueSource(ints = {1, 2})
    void createUser(int p_implementation) {
        createContainer(p_implementation);

        assertThrows(NullPointerException.class,() -> data.createUser(null, "asd"));
        assertThrows(NullPointerException.class,() ->  data.createUser("asd", null));
        assertThrows(NullPointerException.class,() ->  data.createUser(null, null));
        assertThrows(IllegalArgumentException.class,() ->  data.createUser("", "asd"));
        assertThrows(IllegalArgumentException.class,() ->  data.createUser("asd", ""));
        assertThrows(IllegalArgumentException.class,() ->  data.createUser("", ""));

        data.createUser("Mario"," pwd");
        //Provo ad inserire un utente con lo stesso id. Mi aspetto che fallisca
        assertThrows(DuplicatedUserException.class,() ->  data.createUser("Mario", "pwd2"));
        data.createUser("mario"," pwd"); //no case sensitive
    }

    @ParameterizedTest
    @ValueSource(ints = {1, 2})
    void removeUser(int p_implementation) {
        createContainer(p_implementation);

        assertThrows(NullPointerException.class,() ->  data.removeUser(null, "asd"));
        assertThrows(NullPointerException.class,() ->  data.removeUser("asd", null));
        assertThrows(NullPointerException.class,() ->  data.removeUser(null, null));
        assertThrows(IllegalArgumentException.class,() ->  data.removeUser("", "asd"));
        assertThrows(IllegalArgumentException.class,() ->  data.removeUser("asd", ""));
        assertThrows(IllegalArgumentException.class,() ->  data.removeUser("", ""));
        assertThrows(IllegalArgumentException.class, () -> data.removeUser("Luca", "Diavolo!"));

        data.createUser("Mario","pwd");
        data.createUser("mario","pwd");
        assertThrows(CredentialException.class, () ->  data.removeUser("Mario","pwd_err"));
        data.removeUser("Mario","pwd");
        data.createUser("Mario"," pwd"); //Se mario non è stato rimosso questa riga di codice fallisce generando un'eccezzione che non fa passare il test
    }

    @ParameterizedTest
    @ValueSource(ints = {1, 2})
    void getSize(int p_implementation) {
        createContainer(p_implementation);

        assertThrows(NullPointerException.class,() ->  data.getSize(null, "asd"));
        assertThrows(NullPointerException.class,() ->  data.getSize("asd", null));
        assertThrows(NullPointerException.class,() ->  data.getSize(null, null));
        assertThrows(IllegalArgumentException.class,() ->  data.getSize("", "asd"));
        assertThrows(IllegalArgumentException.class,() ->  data.getSize("asd", ""));
        assertThrows(IllegalArgumentException.class,() ->  data.getSize("", ""));

        assertThrows(CredentialException.class,() -> data.getSize("inexistent_user", "fake_pwd"));
        data.createUser("Mario", "pwd");
        data.createUser("Luigi", "pwd");
        assertThrows(CredentialException.class,() -> data.getSize("Mario","pwd_err"));
        assertEquals(0, data.getSize("Mario","pwd"));
        data.put("Mario","pwd",new Exam_SecureWrap(testFolderPath + "/exam1.ser","Analisi",30));
        data.put("Mario","pwd",new Exam_SecureWrap(testFolderPath + "/exam2.ser","PR2",30));
        assertEquals(2,data.getSize("Mario","pwd"));
        assertEquals(0,data.getSize("Luigi","pwd"));
        data.remove("Mario","pwd",new Exam_SecureWrap(testFolderPath + "/exam1.ser","Analisi",30));
        assertEquals(1,data.getSize("Mario","pwd"));
    }

    @ParameterizedTest
    @ValueSource(ints = {1, 2})
    void put(int p_implementation) {
        createContainer(p_implementation);

        assertThrows(NullPointerException.class,() ->  data.put(null, "asd", new Exam_SecureWrap(testFolderPath + "/exam1.ser","Analisi",30)));
        assertThrows(NullPointerException.class,() ->  data.put("asd", null, new Exam_SecureWrap(testFolderPath + "/exam1.ser","Analisi",30)));
        assertThrows(NullPointerException.class,() ->  data.put(null, null,null));
        assertThrows(IllegalArgumentException.class,() ->  data.put("", "asd",new Exam_SecureWrap(testFolderPath + "/exam1.ser","Analisi",30)));
        assertThrows(IllegalArgumentException.class,() ->  data.put("asd", "",new Exam_SecureWrap(testFolderPath + "/exam1.ser","Analisi",30)));

        data.createUser("Mario", "pwd");
        data.createUser("Luigi", "pwd");
        assertThrows(CredentialException.class,() ->  data.put("err", "pwd",new Exam_SecureWrap(testFolderPath + "/exam1.ser","Analisi",30)));
        assertEquals(0, data.getSize("Mario","pwd"));
        assertEquals(0, data.getSize("Luigi","pwd"));
        assertTrue(data.put("Mario","pwd",new Exam_SecureWrap(testFolderPath + "/exam1.ser","Analisi",30)));
        assertTrue(data.put("Mario","pwd",new Exam_SecureWrap(testFolderPath + "/exam2.ser","PR2",30)));
        assertFalse(data.put("Mario","pwd",new Exam_SecureWrap(testFolderPath + "/exam1.ser","Analisi",30)));
        assertFalse(data.put("Luigi","pwd",new Exam_SecureWrap(testFolderPath + "/exam1.ser","Analisi",30)));
    }

    @ParameterizedTest
    @ValueSource(ints = {1, 2})
    void get(int p_implementation) {
        createContainer(p_implementation);

        assertThrows(NullPointerException.class,() ->  data.get(null, "asd", new Exam_SecureWrap(testFolderPath + "/exam1.ser","Analisi",30)));
        assertThrows(NullPointerException.class,() ->  data.get("asd", null, new Exam_SecureWrap(testFolderPath + "/exam1.ser","Analisi",30)));
        assertThrows(NullPointerException.class,() ->  data.get(null, null,null));
        assertThrows(IllegalArgumentException.class,() ->  data.get("", "asd",new Exam_SecureWrap(testFolderPath + "/exam1.ser","Analisi",30)));
        assertThrows(IllegalArgumentException.class,() ->  data.get("asd", "",new Exam_SecureWrap(testFolderPath + "/exam1.ser","Analisi",30)));

        data.createUser("Mario", "pwd");
        data.createUser("Luigi", "pwd");
        Exam_SecureWrap analisi = new Exam_SecureWrap(testFolderPath + "/exam1.ser","Analisi",30);
        Exam_SecureWrap pr2 = new Exam_SecureWrap(testFolderPath + "/exam1.ser","Analisi",30);

        assertThrows(CredentialException.class,() ->  data.put("Mario","pwd_err",analisi));
        data.put("Mario","pwd",analisi);
        assertEquals(analisi, data.get("Mario", "pwd", analisi) );
        assertEquals(1, data.getSize("Mario","pwd") );
        assertEquals(0, data.getSize("Luigi","pwd") );
        assertThrows(NoAccessException.class,() -> data.get("Luigi","pwd",analisi));
        data.shareR("Mario","pwd","Luigi",analisi);
        assertEquals(0, data.getSize("Luigi","pwd") );
        assertEquals(analisi,data.get("Luigi","pwd",analisi));
        Exam_SecureWrap analisi_deepCopy = data.get("Luigi","pwd",analisi);
        analisi_deepCopy.grade = 20;
        assertNotEquals(analisi.grade, analisi_deepCopy.grade);
        data.shareW("Mario","pwd","Luigi",analisi);
        Exam_SecureWrap analisi_directCopy = data.get("Luigi","pwd",analisi);
        analisi_directCopy.grade = 20;
        assertEquals(analisi_directCopy.grade, data.get("Luigi", "pwd", analisi_directCopy).grade);
    }

    @ParameterizedTest
    @ValueSource(ints = {1, 2})
    void remove(int p_implementation) {
        createContainer(p_implementation);

        data.createUser("Mario", "pwd");
        data.createUser("Luigi", "pwd");
        Exam_SecureWrap analisi_mario = new Exam_SecureWrap(testFolderPath + "/exam1.ser","Analisi",30);
        Exam_SecureWrap analisi_luigi = new Exam_SecureWrap(testFolderPath + "/exam2.ser","Analisi",25);
        Exam_SecureWrap pr2_mario = new Exam_SecureWrap(testFolderPath + "/exam3.ser","Analisi",23);
        Exam_SecureWrap pr2_luigi = new Exam_SecureWrap(testFolderPath + "/exam4.ser","Analisi",28);
        Exam_SecureWrap not_inserted = new Exam_SecureWrap(testFolderPath + "/exam5.ser","Analisi",30);

        data.put("Mario","pwd",analisi_mario);
        data.put("Mario","pwd",pr2_mario);
        data.put("Luigi","pwd",analisi_luigi);
        data.put("Luigi","pwd",pr2_luigi);

        data.shareR("Mario","pwd","Luigi",analisi_mario);
        data.shareW("Mario","pwd","Luigi",pr2_mario);

        assertThrows(NullPointerException.class,() ->  data.remove(null, "asd", analisi_mario));
        assertThrows(NullPointerException.class,() ->  data.remove("asd", null, analisi_mario));
        assertThrows(NullPointerException.class,() ->  data.remove("Mario", "pwd", null));
        assertThrows(IllegalArgumentException.class,() ->  data.remove("", "asd", analisi_mario));
        assertThrows(IllegalArgumentException.class,() ->  data.remove("ads", "", analisi_mario));
        assertThrows(IllegalArgumentException.class,() ->  data.remove("Mario", "pwd", not_inserted));
        assertThrows(NoAccessException.class,() ->  data.remove("Mario", "pwd", analisi_luigi));
        assertThrows(NoAccessException.class,() ->  data.remove("Luigi", "pwd", analisi_mario));
        assertThrows(NoAccessException.class,() ->  data.remove("Luigi", "pwd", pr2_mario));

        assertEquals(2, data.getSize("Mario","pwd"));
        assertEquals(2, data.getSize("Luigi","pwd"));
        data.remove("Mario", "pwd", analisi_mario);
        assertEquals(1, data.getSize("Mario","pwd"));
        assertThrows(IllegalArgumentException.class,() -> data.get("Mario","pwd",analisi_mario));
        assertThrows(IllegalArgumentException.class,() -> data.get("Luigi","pwd",analisi_mario));
    }

    @ParameterizedTest
    @ValueSource(ints = {1, 2})
    void copy(int p_implementation) {
        createContainer(p_implementation);
        data.createUser("Mario", "pwd");
        data.createUser("Luigi", "pwd");
        Exam_SecureWrap analisi_mario = new Exam_SecureWrap(testFolderPath + "/exam1.ser","Analisi",30);
        Exam_SecureWrap analisi_luigi = new Exam_SecureWrap(testFolderPath + "/exam2.ser","Analisi",25);
        Exam_SecureWrap pr2_mario = new Exam_SecureWrap(testFolderPath + "/exam3.ser","Analisi",23);
        Exam_SecureWrap pr2_luigi = new Exam_SecureWrap(testFolderPath + "/exam4.ser","Analisi",28);
        Exam_SecureWrap not_inserted = new Exam_SecureWrap(testFolderPath + "/exam5.ser","Analisi",30);

        data.put("Mario","pwd",analisi_mario);
        data.put("Mario","pwd",pr2_mario);
        data.put("Luigi","pwd",analisi_luigi);
        data.put("Luigi","pwd",pr2_luigi);

        data.shareR("Mario","pwd","Luigi",analisi_mario);
        data.shareW("Mario","pwd","Luigi",pr2_mario);

        assertThrows(NullPointerException.class,() ->  data.copy(null, "pwd", analisi_mario, testFolderPath + "/exam6.ser"));
        assertThrows(NullPointerException.class,() ->  data.copy("Mario", null, analisi_mario, testFolderPath + "/exam6.ser"));
        assertThrows(NullPointerException.class,() ->  data.copy("Mario", "pwd", null, testFolderPath + "/exam6.ser"));
        assertThrows(NullPointerException.class,() ->  data.copy("Mario", "pwd", analisi_mario, null));
        assertThrows(IllegalArgumentException.class,() ->  data.copy("", "pwd", analisi_mario, testFolderPath + "/exam6.ser"));
        assertThrows(IllegalArgumentException.class,() ->  data.copy("Mario", "", analisi_mario, testFolderPath + "/exam6.ser"));
        assertThrows(IllegalArgumentException.class,() ->  data.copy("Mario", "pwd", analisi_mario, ""));
        assertThrows(CredentialException.class,() ->  data.copy("Mario", "pwd_err", analisi_mario, testFolderPath + "/exam6.ser"));
        assertThrows(NoAccessException.class,() ->  data.copy("Luigi", "pwd", analisi_mario, testFolderPath + "/exam6.ser"));
        assertThrows(NoAccessException.class,() ->  data.copy("Luigi", "pwd", pr2_mario, testFolderPath + "/exam6.ser"));

        data.copy("Mario", "pwd", analisi_mario, testFolderPath + "/exam6.ser");
        data.copy("Mario", "pwd", pr2_mario, testFolderPath + "/exam7.ser");
        assertEquals(4,data.getSize("Mario","pwd"));
        assertEquals(new Exam_SecureWrap(testFolderPath + "/exam6.ser"),data.get("Mario","pwd",new Exam_SecureWrap(testFolderPath + "/exam6.ser")));
        assertEquals(new Exam_SecureWrap(testFolderPath + "/exam7.ser"),data.get("Mario","pwd",new Exam_SecureWrap(testFolderPath + "/exam7.ser")));
        assertThrows(NoAccessException.class,() -> data.get("Luigi","pwd",new Exam_SecureWrap(testFolderPath + "/exam6.ser")));
        assertThrows(NoAccessException.class,() -> data.get("Luigi","pwd",new Exam_SecureWrap(testFolderPath + "/exam7.ser")));

    }

    @ParameterizedTest
    @ValueSource(ints = {1, 2})
    void shareR(int p_implementation) {
        createContainer(p_implementation);
        data.createUser("Mario", "pwd");
        data.createUser("Luigi", "pwd");
        Exam_SecureWrap analisi_mario = new Exam_SecureWrap(testFolderPath + "/exam1.ser","Analisi",30);
        Exam_SecureWrap analisi_luigi = new Exam_SecureWrap(testFolderPath + "/exam2.ser","Analisi",25);
        Exam_SecureWrap pr2_mario = new Exam_SecureWrap(testFolderPath + "/exam3.ser","Analisi",23);
        Exam_SecureWrap pr2_luigi = new Exam_SecureWrap(testFolderPath + "/exam4.ser","Analisi",28);
        Exam_SecureWrap not_inserted = new Exam_SecureWrap(testFolderPath + "/exam5.ser","Analisi",30);

        data.put("Mario","pwd",analisi_mario);
        data.put("Mario","pwd",pr2_mario);
        data.put("Luigi","pwd",analisi_luigi);
        data.put("Luigi","pwd",pr2_luigi);

        assertThrows(NoAccessException.class,() -> data.get("Luigi","pwd",analisi_mario));

        assertThrows(NullPointerException.class,() ->  data.shareR(null, "pwd", "Luigi", analisi_mario));
        assertThrows(NullPointerException.class,() ->  data.shareR("Mario", null, "Luigi", analisi_mario));
        assertThrows(NullPointerException.class,() ->  data.shareR("Mario", "pwd", null, analisi_mario));
        assertThrows(NullPointerException.class,() ->  data.shareR("Mario", "pwd", "Luigi", null));
        assertThrows(IllegalArgumentException.class,() ->  data.shareR("", "pwd", "Luigi", analisi_mario));
        assertThrows(IllegalArgumentException.class,() ->  data.shareR("Mario", "", "Luigi", analisi_mario));
        assertThrows(IllegalArgumentException.class,() ->  data.shareR("Mario", "pwd", "", analisi_mario));
        assertThrows(CredentialException.class,() ->  data.shareR("Mario", "pwd_err", "Luigi", analisi_mario));
        assertThrows(UnknownUserException.class,() ->  data.shareR("Mario", "pwd", "Luigi_err", analisi_mario));
        assertThrows(IllegalArgumentException.class,() ->  data.shareR("Mario", "pwd", "Mario", analisi_mario));
        assertThrows(NoAccessException.class,() ->  data.shareR("Mario", "pwd", "Luigi", analisi_luigi));

        data.shareR("Mario", "pwd", "Luigi", analisi_mario);
        Exam_SecureWrap analisi_mario_deepCopy = data.get("Luigi","pwd",analisi_mario);
        analisi_mario_deepCopy.grade = 20;
        assertNotEquals(analisi_mario_deepCopy.grade,data.get("Luigi","pwd",analisi_mario).grade);

        Exam_SecureWrap analisi_mario_directCopy = data.get("Mario","pwd",analisi_mario);
        analisi_mario_directCopy.grade = 20;
        assertEquals(analisi_mario_directCopy.grade,data.get("Luigi","pwd",analisi_mario).grade);

    }

    @ParameterizedTest
    @ValueSource(ints = {1, 2})
    void shareW(int p_implementation) {
        createContainer(p_implementation);
        data.createUser("Mario", "pwd");
        data.createUser("Luigi", "pwd");
        Exam_SecureWrap analisi_mario = new Exam_SecureWrap(testFolderPath + "/exam1.ser","Analisi",30);
        Exam_SecureWrap analisi_luigi = new Exam_SecureWrap(testFolderPath + "/exam2.ser","Analisi",25);
        Exam_SecureWrap pr2_mario = new Exam_SecureWrap(testFolderPath + "/exam3.ser","Analisi",23);
        Exam_SecureWrap pr2_luigi = new Exam_SecureWrap(testFolderPath + "/exam4.ser","Analisi",28);
        Exam_SecureWrap not_inserted = new Exam_SecureWrap(testFolderPath + "/exam5.ser","Analisi",30);

        data.put("Mario","pwd",analisi_mario);
        data.put("Mario","pwd",pr2_mario);
        data.put("Luigi","pwd",analisi_luigi);
        data.put("Luigi","pwd",pr2_luigi);

        assertThrows(NoAccessException.class,() -> data.get("Luigi","pwd",analisi_mario));

        assertThrows(NullPointerException.class,() ->  data.shareW(null, "pwd", "Luigi", analisi_mario));
        assertThrows(NullPointerException.class,() ->  data.shareW("Mario", null, "Luigi", analisi_mario));
        assertThrows(NullPointerException.class,() ->  data.shareW("Mario", "pwd", null, analisi_mario));
        assertThrows(NullPointerException.class,() ->  data.shareW("Mario", "pwd", "Luigi", null));
        assertThrows(IllegalArgumentException.class,() ->  data.shareW("", "pwd", "Luigi", analisi_mario));
        assertThrows(IllegalArgumentException.class,() ->  data.shareW("Mario", "", "Luigi", analisi_mario));
        assertThrows(IllegalArgumentException.class,() ->  data.shareW("Mario", "pwd", "", analisi_mario));
        assertThrows(CredentialException.class,() ->  data.shareW("Mario", "pwd_err", "Luigi", analisi_mario));
        assertThrows(UnknownUserException.class,() ->  data.shareW("Mario", "pwd", "Luigi_err", analisi_mario));
        assertThrows(IllegalArgumentException.class,() ->  data.shareW("Mario", "pwd", "Mario", analisi_mario));
        assertThrows(NoAccessException.class,() ->  data.shareW("Mario", "pwd", "Luigi", analisi_luigi));
        data.shareW("Mario", "pwd", "Luigi", analisi_mario);
        assertDoesNotThrow(() -> data.get("Luigi","pwd",analisi_mario));

        data.shareW("Mario", "pwd", "Luigi", analisi_mario);
        Exam_SecureWrap analisi_mario_fromLuigi = data.get("Luigi","pwd",analisi_mario);
        analisi_mario_fromLuigi.grade = 20;
        assertEquals(20,data.get("Luigi","pwd",analisi_mario).grade);

        Exam_SecureWrap analisi_mario_fromMario = data.get("Luigi","pwd",analisi_mario);
        analisi_mario_fromMario.grade = 19;
        assertEquals(19,data.get("Luigi","pwd",analisi_mario_fromMario).grade);

    }

    @ParameterizedTest
    @ValueSource(ints = {1, 2})
    void getIterator(int p_implementation) {
        createContainer(p_implementation);

        data.createUser("Mario", "pwd");
        data.createUser("Luigi", "pwd");
        Exam_SecureWrap analisi_mario = new Exam_SecureWrap(testFolderPath + "/exam1.ser","Analisi",30);
        Exam_SecureWrap analisi_luigi = new Exam_SecureWrap(testFolderPath + "/exam2.ser","Analisi",25);
        Exam_SecureWrap pr2_mario = new Exam_SecureWrap(testFolderPath + "/exam3.ser","Analisi",23);
        Exam_SecureWrap pr2_luigi = new Exam_SecureWrap(testFolderPath + "/exam4.ser","Analisi",28);

        Set<Exam_SecureWrap> mario_exams = new HashSet<>();
        mario_exams.add(analisi_mario);
        mario_exams.add(pr2_mario);

        data.put("Mario","pwd",analisi_mario);
        data.put("Mario","pwd",pr2_mario);
        data.put("Luigi","pwd",analisi_luigi);
        data.put("Luigi","pwd",pr2_luigi);

        data.shareR("Mario","pwd","Luigi",analisi_mario);
        data.shareW("Mario","pwd","Luigi",pr2_mario);

        assertThrows(NullPointerException.class,() -> data.getIterator(null,"pwd"));
        assertThrows(NullPointerException.class,() -> data.getIterator("Mario",null));
        assertThrows(IllegalArgumentException.class,() -> data.getIterator("","pwd"));
        assertThrows(CredentialException.class,() -> data.getIterator("Mario","pwd_err"));

        Iterator<Exam_SecureWrap> iterator = data.getIterator("Mario","pwd");
        while (iterator.hasNext()){
            Exam_SecureWrap cur = iterator.next();
            assertTrue(mario_exams.contains(cur));
        }
    }

    @ParameterizedTest
    @ValueSource(ints = {1, 2})
    void writeFileOnDisk(int p_implementation) {
        createContainer(p_implementation);
        data.createUser("Mario", "pwd");
        data.createUser("Luigi", "pwd");
        Exam_SecureWrap analisi_mario = new Exam_SecureWrap(testFolderPath + "/exam1.ser","Analisi",30);
        Exam_SecureWrap analisi_luigi = new Exam_SecureWrap(testFolderPath + "/exam2.ser","Analisi",25);
        Exam_SecureWrap pr2_mario = new Exam_SecureWrap(testFolderPath + "/exam3.ser","Analisi",23);
        Exam_SecureWrap pr2_luigi = new Exam_SecureWrap(testFolderPath + "/exam4.ser","Analisi",28);
        Exam_SecureWrap not_inserted = new Exam_SecureWrap(testFolderPath + "/exam5.ser","Analisi",30);

        data.put("Mario","pwd",analisi_mario);
        data.put("Mario","pwd",pr2_mario);
        data.put("Luigi","pwd",analisi_luigi);
        data.put("Luigi","pwd",pr2_luigi);

        data.shareR("Mario","pwd","Luigi",analisi_mario);
        data.shareW("Mario","pwd","Luigi",pr2_mario);

        assertThrows(NullPointerException.class,() ->  data.writeFileOnDisk(null,"pwd",analisi_mario));
        assertThrows(NullPointerException.class,() ->  data.writeFileOnDisk("Mario",null, analisi_mario));
        assertThrows(NullPointerException.class,() ->  data.writeFileOnDisk("Mario","pwd", null));
        assertThrows(IllegalArgumentException.class,() ->  data.writeFileOnDisk("","pwd", analisi_mario));
        assertThrows(IllegalArgumentException.class,() ->  data.writeFileOnDisk("Mario","", analisi_mario));
        assertThrows(CredentialException.class,() ->  data.writeFileOnDisk("Mario","pwd_err", analisi_mario));
        assertThrows(NoAccessException.class,() ->  data.writeFileOnDisk("Luigi","pwd", analisi_mario));

        assertThrows(NoAccessException.class,() -> data.writeFileOnDisk("Luigi","pwd", analisi_mario));
        assertTrue(data.writeFileOnDisk("Mario","pwd", analisi_mario));
        data.get("Mario","pwd",analisi_mario).grade = 10;
        assertTrue(data.writeFileOnDisk("Mario","pwd", analisi_mario));
        assertEquals(10,data.get("Mario","pwd",analisi_mario).grade);
    }

    @ParameterizedTest
    @ValueSource(ints = {1, 2})
    void readFileFromDisk(int p_implementation) {
        createContainer(p_implementation);
        data.createUser("Mario", "pwd");
        data.createUser("Luigi", "pwd");
        Exam_SecureWrap analisi_mario = new Exam_SecureWrap(testFolderPath + "/exam1.ser","Analisi",30);
        Exam_SecureWrap analisi_luigi = new Exam_SecureWrap(testFolderPath + "/exam2.ser","Analisi",25);
        Exam_SecureWrap pr2_mario = new Exam_SecureWrap(testFolderPath + "/exam3.ser","Analisi",23);
        Exam_SecureWrap pr2_luigi = new Exam_SecureWrap(testFolderPath + "/exam4.ser","Analisi",28);
        Exam_SecureWrap logica_mario = new Exam_SecureWrap(testFolderPath + "/exam6.ser","Analisi",30);

        data.put("Mario","pwd",analisi_mario);
        data.put("Mario","pwd",pr2_mario);
        data.put("Mario","pwd",logica_mario);
        data.put("Luigi","pwd",analisi_luigi);
        data.put("Luigi","pwd",pr2_luigi);

        data.shareR("Mario","pwd","Luigi",analisi_mario);
        data.shareW("Mario","pwd","Luigi",pr2_mario);

        assertThrows(NullPointerException.class,() ->  data.readFileFromDisk(null,"pwd",analisi_mario));
        assertThrows(NullPointerException.class,() ->  data.readFileFromDisk("Mario",null, analisi_mario));
        assertThrows(NullPointerException.class,() ->  data.readFileFromDisk("Mario","pwd", null));
        assertThrows(IllegalArgumentException.class,() ->  data.readFileFromDisk("","pwd", analisi_mario));
        assertThrows(IllegalArgumentException.class,() ->  data.readFileFromDisk("Mario","", analisi_mario));
        assertThrows(CredentialException.class,() ->  data.readFileFromDisk("Mario","pwd_err", analisi_mario));
        assertFalse( data.readFileFromDisk("Luigi","pwd", analisi_mario));

        assertThrows(NoAccessException.class,() -> data.readFileFromDisk("Luigi","pwd", logica_mario));
        assertFalse(data.readFileFromDisk("Luigi","pwd", analisi_mario));
        assertFalse(data.readFileFromDisk("Luigi","pwd", pr2_mario));
        assertTrue(data.writeFileOnDisk("Mario","pwd", analisi_mario));
        assertTrue(data.writeFileOnDisk("Mario","pwd", pr2_mario));
        assertTrue(data.readFileFromDisk("Luigi","pwd", analisi_mario));
        assertTrue(data.readFileFromDisk("Luigi","pwd", pr2_mario));

        assertTrue(data.readFileFromDisk("Mario","pwd", analisi_mario));
        assertEquals(30,data.get("Mario","pwd",analisi_mario).grade);
    }

    @ParameterizedTest
    @ValueSource(ints = {1, 2})
    void writeContainerOnDisk(int p_implementation) {
        createContainer(p_implementation);
        data.createUser("Mario", "pwd");
        data.createUser("Luigi", "pwd");
        Exam_SecureWrap analisi_mario = new Exam_SecureWrap(testFolderPath + "/exam1.ser","Analisi",30);
        Exam_SecureWrap analisi_luigi = new Exam_SecureWrap(testFolderPath + "/exam2.ser","Analisi",25);
        Exam_SecureWrap pr2_mario = new Exam_SecureWrap(testFolderPath + "/exam3.ser","Analisi",23);
        Exam_SecureWrap pr2_luigi = new Exam_SecureWrap(testFolderPath + "/exam4.ser","Analisi",28);

        data.put("Mario","pwd",analisi_mario);
        data.put("Mario","pwd",pr2_mario);
        data.put("Luigi","pwd",analisi_luigi);
        data.put("Luigi","pwd",pr2_luigi);

        data.shareR("Mario","pwd","Luigi",analisi_mario);
        data.shareW("Mario","pwd","Luigi",pr2_mario);

        //Luca è l'utente admin predefinito. L'admin è l'unico utente che può utilizzare writeContainerOnDisk
        assertThrows(NullPointerException.class,() ->  data.writeContainerOnDisk(null,"pwd"));
        assertThrows(NullPointerException.class,() ->  data.writeContainerOnDisk("Luca",null));
        assertThrows(IllegalArgumentException.class,() ->  data.writeContainerOnDisk("","pwd"));
        assertThrows(IllegalArgumentException.class,() ->  data.writeContainerOnDisk("Luca",""));
        assertThrows(CredentialException.class,() ->  data.writeContainerOnDisk("Luca","pdw_err"));
        assertThrows(CredentialException.class,() ->  data.writeContainerOnDisk("Luigi","pdw"));
        assertTrue(data.writeContainerOnDisk("Luca","Diavolo!"));

    }

    @ParameterizedTest
    @ValueSource(ints = {1, 2})
    void readContainerFromDisk(int p_implementation) {
        createContainer(p_implementation);
        data.createUser("Mario", "pwd");
        data.createUser("Luigi", "pwd");
        Exam_SecureWrap analisi_mario = new Exam_SecureWrap(testFolderPath + "/exam1.ser","Analisi",30);
        Exam_SecureWrap analisi_luigi = new Exam_SecureWrap(testFolderPath + "/exam2.ser","Analisi",25);
        Exam_SecureWrap pr2_mario = new Exam_SecureWrap(testFolderPath + "/exam3.ser","Analisi",23);
        Exam_SecureWrap pr2_luigi = new Exam_SecureWrap(testFolderPath + "/exam4.ser","Analisi",28);

        data.put("Mario","pwd",analisi_mario);
        data.put("Mario","pwd",pr2_mario);
        data.put("Luigi","pwd",analisi_luigi);
        data.put("Luigi","pwd",pr2_luigi);

        data.shareR("Mario","pwd","Luigi",analisi_mario);
        data.shareW("Mario","pwd","Luigi",pr2_mario);

        //Luca è l'utente admin predefinito. L'admin è l'unico utente che può utilizzare writeContainerOnDisk
        assertThrows(NullPointerException.class,() ->  data.readContainerFromDisk(null,"pwd"));
        assertThrows(NullPointerException.class,() ->  data.readContainerFromDisk("Luca",null));
        assertThrows(IllegalArgumentException.class,() ->  data.readContainerFromDisk("","pwd"));
        assertThrows(IllegalArgumentException.class,() ->  data.readContainerFromDisk("Luca",""));
        assertThrows(CredentialException.class,() ->  data.readContainerFromDisk("Luca","pdw_err"));
        assertThrows(CredentialException.class,() ->  data.readContainerFromDisk("Luigi","pdw"));
        assertFalse(data.readContainerFromDisk("Luca","Diavolo!"));
        assertTrue(data.writeContainerOnDisk("Luca","Diavolo!"));
        assertTrue(data.readContainerFromDisk("Luca","Diavolo!"));
    }

    @ParameterizedTest
    @ValueSource(ints = {1, 2})
    void userExist(int p_implementation) {
        createContainer(p_implementation);
        data.createUser("Mario", "pwd");
        data.createUser("Luigi", "pwd");

        assertThrows(NullPointerException.class,()->data.userExist(null));
        assertThrows(IllegalArgumentException.class,()->data.userExist(""));

        assertFalse(data.userExist("Mario_err"));
        assertTrue(data.userExist("Mario"));
        assertFalse(data.userExist("Luigi_err"));
        assertTrue(data.userExist("Luigi"));

    }

    @ParameterizedTest
    @ValueSource(ints = {1, 2})
    void userAuth(int p_implementation) {
        createContainer(p_implementation);
        data.createUser("Mario", "pwd");
        data.createUser("Luigi", "pwd");

        assertThrows(NullPointerException.class,()->data.userAuth(null,"pwd"));
        assertThrows(NullPointerException.class,()->data.userAuth("Mario",null));
        assertThrows(IllegalArgumentException.class,()->data.userAuth("","pwd"));
        assertThrows(IllegalArgumentException.class,()->data.userAuth("Mario",""));

        assertFalse(data.userAuth("Mario","pwd_err"));
        assertFalse(data.userAuth("Mario_err","pwd"));
        assertTrue(data.userAuth("Mario","pwd"));
        assertTrue(data.userAuth("Luigi","pwd"));
    }
}