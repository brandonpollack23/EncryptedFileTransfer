package encryptedfiletransfer;

import javax.crypto.SecretKey;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;

/**
 * Created by brandonpollack on 11/8/15.
 */
public class SimpleFileTransferProtocol {
    static final String requestPubKey = "REQUEST_PUBLIC_KEY\n";
    static final String sendingAESKey = "SENDING_AES_KEY\n";
    static final String sendingFile = "SENDING_FILE\n";

    enum State {
        COMMAND,
        AES_KEY,
        SENDING_FILE
    }

    private ObjectOutputStream oos;
    private ByteArrayOutputStream bs;
    private KeyPair myKeys;

    private SecretKey clientSymKey;

    private State state = State.COMMAND;

    public SimpleFileTransferProtocol() throws IOException {
        oos = new ObjectOutputStream(bs);
    }

    public byte[] process(Object msg) throws NoSuchAlgorithmException, IOException {
        String message = "";
        if(state == State.COMMAND) { //if we are in command state
            message = (String) msg;

            if (message.equalsIgnoreCase(requestPubKey)) { //request public key to encrypt symmetric key with when sending data
                myKeys = KeyGeneration.keyPairGenerate();
                oos.writeObject(myKeys.getPublic());
                return bs.toByteArray();
            }
            else if(message.equalsIgnoreCase(sendingAESKey)){
                state = State.AES_KEY; //next data to come is the AES key
            }
            else if(message.equalsIgnoreCase(sendingFile)) {
                state = State.SENDING_FILE;
            }
        }
        else if(state == State.AES_KEY) { //http://www.macs.hw.ac.uk/~ml355/lore/pkencryption.htm
            //TODO check if sent pub key
            //decrypt with private key and set to clientSymKey
            state = State.COMMAND;
        }
        else if(state == State.SENDING_FILE) {
            //TODO check if recieved sym key
            //depcrypte and write to file output
            state = State.COMMAND;
        }
        else {
            throw new IllegalStateException("No such state for the protocol!");
        }
    }
}
