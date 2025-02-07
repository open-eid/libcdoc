package ee.ria.cdoc;

public class CDocException extends java.lang.Exception {
    public final int code;
    CDocException(int code, String msg) {
        super(msg);
        this.code = code;
    }
}
