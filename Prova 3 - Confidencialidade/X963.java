import java.util.Scanner;
import java.util.Base64;
import com.dinamonetworks.Dinamo;
import br.com.trueaccess.TacException;
import br.com.trueaccess.TacNDJavaLib;
import java.util.Arrays;


public class X963 {
    static String hsmIP = "187.33.9.132";
    static String hsmUser = "utfpr1";
    static String hsmPass = "segcomp20241";

    public static void main(String[] args) throws Exception {
        Dinamo api = new Dinamo();
        Scanner scanner = new Scanner(System.in);

        String clientKey = "key_client";
        String serverKey = "key_server";

        try {
            api.openSession(hsmIP, hsmUser, hsmPass, false);
            api.deleteKeyIfExists(serverKey);
            api.deleteKeyIfExists(clientKey);

            String cPKB64 = scanner.nextLine();
            byte[] cPKByte = Base64.getDecoder().decode(cPKB64);

            api.importKey(clientKey, TacNDJavaLib.PRIVATEKEY_BLOB, TacNDJavaLib.ALG_ECC_SECP128R1, 0, cPKByte, cPKByte.length);
            api.createKey(serverKey, TacNDJavaLib.ALG_ECC_SECP128R1);

            byte[] sPUByte = api.exportKey(serverKey, TacNDJavaLib.PUBLICKEY_BLOB);
            byte[] kdfData = api.getRand(16);
             
            //ECDH Raw -> Combina PK cliente e PU server e retorna segredo matematico
            byte[] rawSecretByte = api.genEcdhKey(TacNDJavaLib.DN_GEN_KEY_KDF_RAW_SECRET, clientKey, sPUByte);

            //ECDH X963 -> Mistura segredo puro e KDF aleatório -> Hash 256 -> AES 128
            byte[] x963SecretByte = api.genEcdhKeyX963Sha256(clientKey, null, TacNDJavaLib.ALG_AES_128, false, false, sPUByte, kdfData);

            System.out.println("Raw: " + Base64.getEncoder().encodeToString(rawSecretByte));
            System.out.println("X963: " + Base64.getEncoder().encodeToString(x963SecretByte));
        }
        catch (TacException e) {
            System.out.println("Erro no HSM: " + e.getMessage());
        }
        finally {
            api.deleteKeyIfExists(serverKey);
            api.deleteKeyIfExists(clientKey);
            api.closeSession();
            scanner.close();
        }
    }
}
