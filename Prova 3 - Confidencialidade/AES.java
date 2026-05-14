import java.nio.charset.StandardCharsets;
import java.util.Scanner;
import java.util.Base64;
import com.dinamonetworks.Dinamo;
import br.com.trueaccess.TacException;
import br.com.trueaccess.TacNDJavaLib;


public class AES {
    static String hsmIP = "187.33.9.132";
    static String hsmUser = "utfpr1";
    static String hsmPass = "segcomp20241";

    public static void main(String[] args) throws Exception {
        Dinamo api = new Dinamo();
        Scanner scanner = new Scanner(System.in);
        String keyId = "Key_Ex1_P3";

        try {
            api.openSession(hsmIP, hsmUser, hsmPass, false);
            byte[] ivByte = api.getRand(16);


            String M = scanner.nextLine();
            byte[] MByte = M.getBytes(StandardCharsets.UTF_8);

            api.deleteKeyIfExists(keyId);
            api.createKey(keyId, TacNDJavaLib.ALG_AES_128);

            byte[] cryptByte = api.encrypt(keyId, MByte, ivByte, TacNDJavaLib.D_PKCS5_PADDING, TacNDJavaLib.MODE_CBC);
            byte[] decriptByte = api.decrypt(keyId, cryptByte, ivByte, TacNDJavaLib.D_PKCS5_PADDING, TacNDJavaLib.MODE_CBC);

            String decriptTXT = new String(decriptByte, StandardCharsets.UTF_8);
            String cryptB64 = Base64.getEncoder().encodeToString(cryptByte);

            if (M.equals(decriptTXT)) {
                System.out.println("Validação OK");
            }
            else {
                System.out.println("Erro na validação");
            }

            System.out.println(cryptB64);
        }
        catch (TacException e) {
            System.err.println("Erro no HSM: " + e.getMessage());
        } finally {
            api.deleteKeyIfExists(keyId);
            api.closeSession();
            scanner.close();
        }
    }
}
