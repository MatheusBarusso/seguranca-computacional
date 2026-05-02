import java.util.Scanner;
import com.dinamonetworks.Dinamo;
import br.com.trueaccess.TacException;
import br.com.trueaccess.TacNDJavaLib;
import java.util.HexFormat;


public class Sha256_256 {
    static String hsmIP = "187.33.9.132";
    static String hsmUser = "utfpr1";
    static String hsmPass = "segcomp20241";

    public static void main(String[] args) throws Exception{
        Dinamo api = new Dinamo();
        Scanner scanner = new Scanner(System.in);
        api.openSession(hsmIP, hsmUser, hsmPass, false);

        String M = scanner.nextLine();
        byte[] mensagem = M.getBytes();

        byte[] hash1 = api.generateHash(TacNDJavaLib.ALG_SHA2_256, mensagem);
        byte[] hash2 = api.generateHash(TacNDJavaLib.ALG_SHA2_256, hash1);

        String hex = HexFormat.of().formatHex(hash2);
        
        System.out.println("SHA256 x SHA256: " + hex);

        scanner.close();
        api.closeSession();
    }
}