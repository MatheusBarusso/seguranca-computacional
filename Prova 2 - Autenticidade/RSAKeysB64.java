import java.util.Scanner;
import com.dinamonetworks.Dinamo;
import br.com.trueaccess.TacException;
import br.com.trueaccess.TacNDJavaLib;
import java.util.Base64;

public class RSAKeysB64 {
    public static void main(String[] args) throws TacException {

    Dinamo api = new Dinamo();
    Scanner scanner = new Scanner(System.in);

    String keyID = "chave_rsa_usuario";

        try {
            String M = scanner.nextLine();
            api.openSession("187.33.9.132", "utfpr1", "segcomp20241", false);

            try { api.deleteKey(keyID); } catch (TacException e) {}

            api.createKey(keyID, TacNDJavaLib.ALG_RSA_2048);

            byte[] mByte = M.getBytes();
            byte[] signature = api.sign(keyID, TacNDJavaLib.ALG_SHA2_256, mByte);

            String signatureB64 = Base64.getEncoder().encodeToString(signature);

            System.out.println("Mensagem: " + M);
            System.out.println("Signature B64: " + signatureB64);

        }
        finally {
            scanner.close();
            api.closeSession();
        }
    }
}
