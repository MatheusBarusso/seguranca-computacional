import com.dinamonetworks.Dinamo;
import br.com.trueaccess.TacException;
import br.com.trueaccess.TacNDJavaLib;
import java.util.Base64;


public class Key_Gen {
    static String hsmIP = "187.33.9.132";
    static String hsmUser = "utfpr1";
    static String hsmPass = "segcomp20241";

    public static void main(String[] args) throws Exception {
        Dinamo api = new Dinamo();
        String keyId = "chave_temp_client";

        try {
            api.openSession(hsmIP, hsmUser, hsmPass, false);

            try {api.deleteKeyIfExists(keyId);} catch (TacException e) {}

            api.createKey(keyId, TacNDJavaLib.ALG_ECC_SECP128R1);

            byte[] PKByte = api.exportKey(keyId, TacNDJavaLib.PRIVATEKEY_BLOB);
            String PKB64 = Base64.getEncoder().encodeToString(PKByte);

            System.out.println(PKB64);

            api.deleteKey(keyId);
        }
        finally {
            api.closeSession();
        }
    
    
    
    }
}


