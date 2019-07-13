import SecureContainer.SecureFile;

class Exam_SecureWrap extends SecureFile {
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
