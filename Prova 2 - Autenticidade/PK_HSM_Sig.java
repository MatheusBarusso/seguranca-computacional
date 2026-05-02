import java.util.Scanner;
import com.dinamonetworks.Dinamo;
import br.com.trueaccess.TacException;
import br.com.trueaccess.TacNDJavaLib;
import java.util.Base64;

public class PK_HSM_Sig {
    public static void main(String[] args) throws TacException {
        Dinamo api = new Dinamo();
        Scanner scanner = new Scanner(System.in);

        String keyID = "chave_importada";

        try {
            System.out.print("Digite a mensagem M: ");
            String M = scanner.nextLine();

            System.out.print("Digite a PK RSA B64: ");
            String PKRSAB64 = scanner.nextLine();

            System.out.print("Digite a Signature RSA B64: ");
            String SigRSAB64 = scanner.nextLine();

            api.openSession("187.33.9.132", "utfpr1", "segcomp20241", false);

            byte[] mByte = M.getBytes();
            byte[] pkByte = Base64.getDecoder().decode(PKRSAB64.trim());
            byte[] sgByte = Base64.getDecoder().decode(SigRSAB64.trim());
            
            try {api.deleteKey(keyID);} catch (TacException e) {}

            api.importKey(keyID, TacNDJavaLib.PUBLICKEY_BLOB_HSM, TacNDJavaLib.ALG_OBJ_PUBKEY_SPKI_RSA_BLOB, 0, pkByte);

            try {
                api.verifySignature(keyID, TacNDJavaLib.ALG_SHA2_256, sgByte, mByte);
                System.out.println("Assinatura válida");

            } catch (TacException e) {
                System.out.println("Assinatura inválida. Motivo: " + e.getMessage());
            }

            api.deleteKey(keyID);
        } finally {
            scanner.close();
            api.closeSession();
        }
    }
}
