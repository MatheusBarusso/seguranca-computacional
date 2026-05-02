import java.util.Scanner;
import com.dinamonetworks.Dinamo;
// import br.com.trueaccess.TacException;
import br.com.trueaccess.TacNDJavaLib;
import java.util.HexFormat;


public class Sha256_512 {
    static String hsmIP = "187.33.9.132";
    static String hsmUser = "utfpr1";
    static String hsmPass = "segcomp20241";

    public static void main(String[] args) throws Exception{
        Dinamo api = new Dinamo();
        Scanner scanner = new Scanner(System.in);
        api.openSession(hsmIP, hsmUser, hsmPass, false);

        String M = scanner.nextLine();
        byte[] mensagem = M.getBytes();

        byte[] hash512 = api.generateHash(TacNDJavaLib.ALG_SHA2_512, mensagem);
        byte[] hash256 = api.generateHash(TacNDJavaLib.ALG_SHA2_256, mensagem);

        String hex256 = HexFormat.of().formatHex(hash256);
        String hex512 = HexFormat.of().formatHex(hash512);
        
        System.out.println("SHA256: " + hex256);
        System.out.println("SHA512: " + hex512);

        scanner.close();
        api.closeSession();
    }
}