import java.util.Scanner;
import com.dinamonetworks.Dinamo;
import br.com.trueaccess.TacException;
import br.com.trueaccess.TacNDJavaLib;
import java.util.HexFormat;

public class HMAC {
    static String hsmIP = "187.33.9.132";
    static String hsmUser = "utfpr1";
    static String hsmPass = "segcomp20241";
    static String chave = "hmac_key";

    public static void main(String[] args) throws TacException {
        Dinamo api = new Dinamo();
        Scanner scanner = new Scanner(System.in);
        api.openSession(hsmIP, hsmUser, hsmPass, false);

        // api.createKey(chave, TacNDJavaLib.ALG_HMAC_SHA2_256, true);

        String entrada = scanner.nextLine();
        byte[] msg_byte = entrada.getBytes();

        byte[] hmac = api.generateMAC(TacNDJavaLib.ALG_HMAC_SHA2_256, chave, msg_byte);

        String hex = HexFormat.of().formatHex(hmac);
        System.out.println(hex);

        scanner.close();
        api.closeSession();
    }
}
