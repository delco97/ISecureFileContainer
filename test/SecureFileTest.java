import SecureContainer.ISecureFileContainer;
import SecureContainer.SecureFile;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import javax.swing.filechooser.FileSystemView;
import java.io.File;
import java.nio.file.Path;
import java.nio.file.Paths;

import static org.junit.jupiter.api.Assertions.*;

class SecureFileTest {
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
    @Test
    void getFilePath() {
        Exam_SecureWrap e1 = new Exam_SecureWrap(testFolderPath + "/exam1.ser","Analisi",30);
        Exam_SecureWrap e2 = new Exam_SecureWrap(testFolderPath + "/exam1.ser","PR2",30);
        SecureFile e3 = new Exam_SecureWrap(testFolderPath + "/exam2.ser","Fisica",30);

        assertEquals(testFolderPath + "/exam1.ser",e1.getFilePath());
        assertEquals(testFolderPath + "/exam1.ser",e2.getFilePath());
        assertEquals(testFolderPath + "/exam2.ser",e3.getFilePath());
    }

    @Test
    void _equals() {
        Exam_SecureWrap e1 = new Exam_SecureWrap(testFolderPath + "/exam1.ser","Analisi",30);
        Exam_SecureWrap e2 = new Exam_SecureWrap(testFolderPath + "/exam1.ser","PR2",30);
        SecureFile e3 = new Exam_SecureWrap(testFolderPath + "/exam2.ser","Fisica",30);
        Exam_SecureWrap e4 = new Exam_SecureWrap(testFolderPath + "/exam2.ser","Logica",30);

        assertFalse(e1.equals(1));
        assertFalse(e1.equals(testFolderPath + "/exam1.ser"));
        assertTrue(e1.equals(e2));
        assertTrue(e2.equals(e1));
        assertTrue(e3.equals(e4));
        assertTrue(e4.equals(e3));
    }
}