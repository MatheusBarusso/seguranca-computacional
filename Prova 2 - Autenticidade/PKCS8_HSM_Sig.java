import java.util.Scanner;
import com.dinamonetworks.Dinamo;
import br.com.trueaccess.TacException;
import br.com.trueaccess.TacNDJavaLib;
import java.util.Base64;

public class PKCS8_HSM_Sig {
    public static void main(String[] args) throws TacException {
        Dinamo api = new Dinamo();
        Scanner scanner = new Scanner(System.in);

        String keyId = "chave_privada_pkcs8";

        try {
            System.out.print("Digite a mensagem M: ");
            String M = scanner.nextLine();

            System.out.print("Digite a PK B64: ");
            String PKB64 = scanner.nextLine();

            api.openSession("187.33.9.132", "utfpr1", "segcomp20241", false);

            byte[] pkByte = Base64.getDecoder().decode(PKB64.trim());
            byte[] mByte = M.getBytes();

            try { api.deleteKey(keyId);} catch (Exception e) {}

            api.PKCS8ImportKey(keyId, null, TacNDJavaLib.ALG_RSA_2048, pkByte, true);

            byte[] sigByte = api.sign(keyId, TacNDJavaLib.ALG_SHA2_256, mByte);
            
            String sigB64 = Base64.getEncoder().encodeToString(sigByte);

            System.out.println("Assinatura em B64: " + sigB64);

            api.deleteKey(keyId);

        } finally {
            scanner.close();
            api.closeSession();
        }
    }
}
