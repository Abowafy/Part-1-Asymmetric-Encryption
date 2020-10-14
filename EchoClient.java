import java.io.*;
import java.net.*;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.util.Scanner;
import java.nio.charset.StandardCharsets;
import javax.crypto.Cipher;

public class EchoClient {

    private Socket clientSocket;
    private DataOutputStream out;
    private DataInputStream in;
    public static final String cipherName = "RSA/ECB/PKCS1Padding";

    /**
     * Setup the two way streams.
     *
     * @param ip the address of the server
     * @param port port used by the server
     *
     */
    public void startConnection(String ip, int port) {
        try {
            clientSocket = new Socket(ip, port);
            out = new DataOutputStream(clientSocket.getOutputStream());
            in = new DataInputStream(clientSocket.getInputStream());
        } catch (IOException e) {
            System.out.println("Error when initializing connection");
        }
    }

    /**
     * Send a message to server and receive a reply.
     *
     * @param msg the message to send
     */
    public String sendMessage(String msg,PrivateKey privateKey,String publicKeyDestibation) {
        try {
            System.out.println("Client sending cleartext "+msg);
            
            final byte[] originalBytes = msg.getBytes(StandardCharsets.UTF_8);
            Cipher cipher = Cipher.getInstance(cipherName);
            cipher.init(Cipher.ENCRYPT_MODE, Util.convertStringtoPublicKey(publicKeyDestibation));
            byte[] data = cipher.doFinal(originalBytes);
            //Sign here
            Signature sig = Signature.getInstance("SHA256withRSA");
            sig.initSign(privateKey);
            sig.update(originalBytes);
            byte[] signatureBytes = sig.sign();
            
            
            //byte[] data = msg.getBytes("UTF-8");
            // encrypt data
            //System.out.println("Client sending ciphertext "+Util.bytesToHex(data));
            out.write(data);
            out.flush();
            in.read(data);
            // decrypt data
            String reply = new String(data, "UTF-8");
            System.out.println("Server returned cleartext "+reply);
            return reply;
        } catch (Exception e) {
            System.out.println(e.getMessage());
            return null;
        }
    }

    /**
     * Close down our streams.
     *
     */
    public void stopConnection() {
        try {
            in.close();
            out.close();
            clientSocket.close();
        } catch (IOException e) {
            System.out.println("error when closing");
        }
    }

    public static void main(String[] args) throws Exception{
        EchoClient client = new EchoClient();
        client.startConnection("127.0.0.1", 4444);
        //1.
        //create key client pair
        final KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        final KeyPair kp = kpg.generateKeyPair(); //The same as genKeyPair
        //public key
        final PublicKey publicKey = kp.getPublic();
        //private key
        final PrivateKey privateKey = kp.getPrivate();
         
        //print to console
        String str_key = Util.convertPublicKeyToString(publicKey);

        System.out.println("Client public key is " +str_key);
        //System.out.println(" Our Hex-Encoded is " + Util.bytesToHex(publicKey.getEncoded()));
        //System.out.println("Private key is " + privateKey);
        
        //2.
        //Allow user  Enter public key for destination
        Scanner input = new Scanner(System.in);
        String publicKeyDestibation = input.nextLine();
        
        //3
        //Encrypt and sign message to the destination
        
        //Can use other cipher names, like "RSA/ECB/PKCS1Padding"
        //Cipher cipher = Cipher.getInstance(cipherName);
        //cipher.init(Cipher.ENCRYPT_MODE, Util.convertStringtoPublicKey(publicKeyDestibation));
        
        //message to send
        String original = "12345678";
        //final byte[] originalBytes = original.getBytes(StandardCharsets.UTF_8);
        //byte[] cipherTextBytes = cipher.doFinal(originalBytes);
        //Sign here
        //Signature sig = Signature.getInstance("SHA256withRSA");
        //sig.initSign(privateKey);
        //sig.update(originalBytes);
        //byte[] signatureBytes = sig.sign();
        
        
        
        client.sendMessage("12345678",privateKey,publicKeyDestibation);
        //client.sendMessage("ABCDEFGH");
        //client.sendMessage("87654321");
        //client.sendMessage("HGFEDCBA");
        //client.stopConnection();
    }
}
