import java.net.*;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.util.Scanner;

import javax.crypto.Cipher;

import java.io.*;

public class EchoServer {

    private ServerSocket serverSocket;
    private Socket clientSocket;
    private DataOutputStream out;
    private DataInputStream in;

    /**
     * Create the server socket and wait for a connection.
     * Keep receiving messages until the input stream is closed by the client.
     *
     * @param port the port number of the server
     */
    public void start(int port) throws Exception{
        try {
            serverSocket = new ServerSocket(port);
            //create key client pair
            final KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(2048);
            final KeyPair kp = kpg.generateKeyPair(); //The same as genKeyPair
            //public key
            final PublicKey publicKey = kp.getPublic();
            //private key
            final PrivateKey privateKey = kp.getPrivate();
            //print to console
            //System.out.println("Server public key is " + publicKey);
            String str_key = Util.convertPublicKeyToString(publicKey);

            System.out.println("Server public key is " +str_key);
            clientSocket = serverSocket.accept();
            out = new DataOutputStream(clientSocket.getOutputStream());
            in = new DataInputStream(clientSocket.getInputStream());
            
           
            
            //Allow user Enter public key for destination
            Scanner input = new Scanner(System.in);
            String publicKeyDestibation = input.nextLine();
            
            
            byte[] data = new byte[256];
            int numBytes;
            
            //Encrypt and sign message to the destination
            final String cipherName = "RSA/ECB/PKCS1Padding";
            //Can use other cipher names, like "RSA/ECB/PKCS1Padding"
            Cipher cipher = Cipher.getInstance(cipherName);
            while ((numBytes = in.read(data)) != -1) {
            	// Decrypt
                cipher.init(Cipher.DECRYPT_MODE, privateKey);
                byte[] decryptedBytes = cipher.doFinal(data);
                String decryptedString = new String(decryptedBytes, StandardCharsets.UTF_8);

                //System.out.println("Original:\t" + original);
                System.out.println("Encrypted:\t" + Util.bytesToHex(data));
                System.out.println("Decrypted:\t" + decryptedString);
                
                /*
                System.out.println("Checking signature...");
                Signature sig = Signature.getInstance("SHA256withRSA");
                sig.initVerify(Util.convertStringtoPublicKey(publicKeyDestibation));
                sig.update(decryptedBytes);
                final boolean signatureValid = sig.verify(decryptedBytes);
                if (signatureValid) {
                    System.out.println("Yes, Client wrote this. Notice where Client/Server keys are used.");
                } else {
                    throw new IllegalArgumentException("Signature does not match");
                }
                
                */
            }
            stop();
        } catch (IOException e) {
            System.out.println(e.getMessage());
        }

    }

    /**
     * Close the streams and sockets.
     *
     */
    public void stop() {
        try {
            in.close();
            out.close();
            clientSocket.close();
            serverSocket.close();
        } catch (IOException e) {
            System.out.println(e.getMessage());
        }

    }

    public static void main(String[] args) throws Exception{
        EchoServer server = new EchoServer();
        server.start(4444);
    }

}



