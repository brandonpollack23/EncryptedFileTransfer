package encryptedfiletransfer;

import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.InetAddress;
import java.net.Socket;

/**
 * Created by brandonpollack on 11/10/15.
 */
public class ClientFunctions {
    /**
     * send a file to the server using the correct protocol
     * @param server
     * @param file
     * @throws Exception
     */
    public static void sendFileToServer(Socket server, File file) throws Exception {
        FileInputStream inFile = new FileInputStream(file);

        OutputStream out = new BufferedOutputStream(server.getOutputStream());
        InputStream in = new BufferedInputStream(server.getInputStream());

        //get the server public key to encrypt the symmetric key with
        byte[] serverPublicKey = requestKeyFromServerBlocking(out, in);


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

        sendEncryptedSymmetricKey(cipherOut, out, symmetricKey);

        cipherOut = new CipherOutputStream(out, aesCipher);

        sendEncryptedFileToServer(cipherOut, out, inFile);

        cipherOut.close();
        server.close();
        inFile.close();
    }

    /**
     * connects to a server and returns the socket
     * @param address
     * @param port
     * @return Socket wiht server address
     */
    public static Socket connectToServer(InetAddress address, int port) throws IOException {
        return new Socket(address, port);
    }

    /**
     * requests a public RSA key to encrypt AES key with
     * @param out
     * @param in
     * @return
     * @throws IOException
     */
    private static byte[] requestKeyFromServerBlocking(OutputStream out, InputStream in) throws IOException {
        //first send request
        out.write(SimpleFileTransferProtocol.requestPubKey.getBytes());
        out.write("\n".getBytes());
        out.flush();

        //now block and wait for the public key
        byte[] key = new byte[256];
        in.read(key, 0, 256);
        return key;
    }

    /**
     * copy from one stream to another
     * @param is
     * @param os
     * @throws Exception
     */
    private static void copy(InputStream is, OutputStream os) throws IOException {
        int i;
        byte[] b = new byte[1024];
        while((i = is.read(b))!= -1) {
            os.write(b, 0, i);
        }
    }

    /**
     * write the command to let the server know we're sending aeskey and then write it
     * send encrypted AES key
     * @param cipherOut
     * @param symmetricKey
     */
    private static void sendEncryptedSymmetricKey(CipherOutputStream cipherOut, OutputStream out, byte[] symmetricKey) throws IOException {
        //send command
        out.write(SimpleFileTransferProtocol.sendingAESKey.getBytes());
        out.write("\n".getBytes());
        out.flush();

        //send the key
        cipherOut.write(symmetricKey);
        cipherOut.flush();
    }

    private static void sendEncryptedFileToServer(CipherOutputStream cipherOut, OutputStream out, FileInputStream inFile) throws IOException {
        //send command
        out.write(SimpleFileTransferProtocol.sendingFile.getBytes());
        out.write("\n".getBytes());
        out.flush();

        //send the file
        copy(inFile, cipherOut);
        cipherOut.flush();
    }
}
