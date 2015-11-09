package encryptedfiletransfer;

import java.security.*;

/**
 * Created by brandonpollack on 11/8/15.
 */
public class KeyGeneration {
    public static KeyPair keyPairGenerate() throws NoSuchAlgorithmException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        return keyGen.genKeyPair();
    }
}
