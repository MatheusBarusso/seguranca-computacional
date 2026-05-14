import com.dinamonetworks.Dinamo;
import br.com.trueaccess.TacException;
import br.com.trueaccess.TacNDJavaLib;
import java.util.Arrays;
import java.util.Base64;
import java.util.Scanner;


public class KT_Protocol {
    static String hsmIP = "187.33.9.132";
    static String hsmUser = "utfpr1";
    static String hsmPass = "segcomp20241";

    public static void main(String[] args) throws Exception {
        Dinamo api = new Dinamo();
        Scanner scanner = new Scanner(System.in);
        String keyId = "keyid_ex3_p3";

        byte[][] K = new byte[7][32];
        byte[][] C = new byte[7][256];
        String[] C64 = new String[7];


        try {
            api.deleteKeyIfExists(keyId);
            api.createKey(keyId, TacNDJavaLib.ALG_RSA_2048, TacNDJavaLib.EXPORTABLE_KEY);

            for (int i = 0; i < 7; i++) {
                //Gerar K random 32 bytes no HSM
                K[i] = api.getRand(32);
                
                //Cifra K usando PU RSA gerando envelope seguro C
                C[i] = api.encrypt(keyId, K[i]);

                //Exibe em B64
                C64[i] = Base64.getEncoder().encodeToString(C[i]);
                System.out.println("C64["+ i +"](Segredo cifrado em B64): " + C64[i]);
            }

            for (int j = 0; j < 7; j++) {
                byte[] decrypByte = api.decrypt(keyId, C[j]);
                if (!Arrays.equals(K[j], decrypByte)) {
                    System.out.println("Erro: K["+ j + "] não corresponde ao valor original após decriptação;");
                    return;
                }
                else {
                    System.out.println("Sucesso");
                }
            }

            byte[][] KHashByte = new byte[7][32];

            for (int k = 0; k < 7; k++) {
                KHashByte[k] = api.generateHash(TacNDJavaLib.ALG_SHA2_256, K[k]);
            }


            byte[][] KchaveByte = new byte[7][16];
            byte[][] KivByte = new byte[7][16];
            String keyAES = "AESKey";

            for (int m = 0; m < 7; m++) {
                KchaveByte[m] = Arrays.copyOfRange(KHashByte[m], 0, 16);
                KivByte[m] = Arrays.copyOfRange(KHashByte[m], 16, 32);

                api.deleteKeyIfExists(keyAES);
                api.importKey(keyAES, TacNDJavaLib.PLAINTEXTKEY_BLOB, TacNDJavaLib.ALG_AES_128, KchaveByte[m], true);

                System.out.print("Digite a palavra/mensagem " + (m + 1) + " a ser cifrada: ");
                String mUser = scanner.nextLine();
                byte[] TxtByte = mUser.getBytes();

                byte[] encrypt = api.encrypt(keyAES, TxtByte, KivByte[m], TacNDJavaLib.D_PKCS5_PADDING, TacNDJavaLib.MODE_CBC);

                String encrypted64 = Base64.getEncoder().encodeToString(encrypt);
                System.out.println("=> Encrypted[" + m + "] (Mensagem em base64): " + encrypted64 + "\n");
                api.deleteKey(keyAES); 
                
            }
        }
        finally {
            api.deleteKey(keyId);
            api.closeSession();
            scanner.close();
        }
    }
}
