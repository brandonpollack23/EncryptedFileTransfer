package encryptedfiletransfer;

import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;

/**
 * Created by brandonpollack on 11/8/15.
 */

public class Main {
    static final int PORT_NUMBER = 4718;

    public static void main(String[] args) {
        //TODO parse args for address, if there is none you're the server
    }

    /**
     * connects to a server and returns the socket
     * @param address
     * @param port
     * @return Socket wiht server address
     */
    public Socket connectToServer(InetAddress address, int port) throws IOException {
        return new Socket(address, port);
    }

    public void sendFileToServer(Socket server, File file) throws Exception {
        FileInputStream inFile = new FileInputStream(file);

        ObjectOutputStream out = new ObjectOutputStream(server.getOutputStream());
        ObjectInputStream in = new ObjectInputStream(server.getInputStream());
        out.writeObject(SimpleFileTransferProtocol.requestPubKey); //request public key from socket

        //get the server public key to encrypt the symmetric key with
        byte[] serverPublicKey = ((PublicKey) in.readObject()).getEncoded(); //protocol will send the public key

        //encrypt aes key with the server's public key for safe transmission
        KeyGenerator keygen = KeyGenerator.getInstance("RSA");
        Cipher pkCipher = Cipher.getInstance("RSA");
        pkCipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(serverPublicKey, "RSA"));
        CipherOutputStream cipherOut = new CipherOutputStream(out, pkCipher);

        //create the AES key cipher
        keygen = KeyGenerator.getInstance("AES");
        keygen.init(256);
        byte[] symmetricKey = keygen.generateKey().getEncoded();
        Cipher aesCipher = Cipher.getInstance("AES");
        aesCipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(symmetricKey, "AES"));

        //send protocol command for sending AES key
        out.writeObject(SimpleFileTransferProtocol.sendingAESKey);

        //send the aes key encrypted with the public key form the server
        cipherOut.write(symmetricKey);

        //tell server we're sending file
        out.writeObject(SimpleFileTransferProtocol.sendingFile);

        //send the file encrypted with the aes key
        cipherOut = new CipherOutputStream(out, aesCipher);
        copy(inFile, cipherOut);

        cipherOut.close();
        server.close();
    }

    private void copy(InputStream is, OutputStream os) throws Exception {
        int i;
        byte[] b = new byte[1024];
        while((i = is.read(b))!= -1) {
            os.write(b, 0, i);
        }
    }

    /**
     * listens for a connection and blocks until there is one and returns the socket
     * @return
     */
    public Socket listenForConnectionBlocking() throws IOException {
        ServerSocket sock = new ServerSocket(PORT_NUMBER);
        return sock.accept();
    }
}
