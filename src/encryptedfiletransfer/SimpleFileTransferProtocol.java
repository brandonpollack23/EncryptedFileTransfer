package encryptedfiletransfer;

import javax.crypto.SecretKey;
import java.io.*;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;

/**
 * Created by brandonpollack on 11/8/15.
 */
public class SimpleFileTransferProtocol {
    static final String requestPubKey = "REQUESTRSAKEY\n";
    static final String sendingAESKey = "SENDINGAES   \n";
    static final String sendingFile = "SENDINGFILE  \n"; //all commands must be 14 char plus the extra newline

    static final String unrecognizedCommand = "Unrecognized Command"

    public ServerOperationData process(InputStream is) throws NoSuchAlgorithmException, IOException {
        String command = readCommand(is);

        if(command == null) {
            return new ServerOperationData<String>(unrecognizedCommand.getBytes(), null);
        }
        else if (command.contains(requestPubKey)) { //request public key to encrypt symmetric key with when sending data
            KeyPair myKeys = keyPairGenerate();
            return new ServerOperationData<KeyPair>(myKeys.getPublic().getEncoded(), myKeys); //TODO server should save myKeys
        }
        else if(command.contains(sendingAESKey)){
        }
        else if(command.contains(sendingFile)) {
        }
        else {
            //TODO ERROR
        }

        //TODO handle getting AES key
        //TODO handle getting file, make sure to check if we have key
    }

    public static String readCommand(InputStream is) throws IOException {
        byte[] buf = new byte[15];
        is.read(buf, 0, 15);

        return new String(buf);
    }

    public static KeyPair keyPairGenerate() throws NoSuchAlgorithmException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        return keyGen.genKeyPair();
    }

    public class ServerOperationData<T> {
        final public byte[] returnToClient;
        final T other;

        public ServerOperationData(byte[] returnToClient, T other) {
            this.returnToClient = returnToClient;
            this.other = other;
        }
    }
}
