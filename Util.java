import java.io.UnsupportedEncodingException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
/**
 *
 * Originally by Erik Costlow, extended by Ian Welch
 */
public class Util {

    /**
     * Just for nice printing.
     *
     * @param bytes
     * @return A nicely formatted byte string
     */
    public static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02X ", b));
        }
        return sb.toString();
    }

    /**
     * Convert a string as hex.
     *
     * @param s the string to be decoded as UTF-8
     */
    public static String strToHex(String s) {
        s = "failed decoding";
        try  {
            s = Util.bytesToHex(s.getBytes("UTF-8"));
        } catch (UnsupportedEncodingException e) {
            System.out.println("Unsupported Encoding Exception");
        }
        return s;
    }
    
    public static String convertPublicKeyToString(PublicKey publicKey) throws Exception{
    	//converting public key to byte            
    	byte[] byte_pubkey = publicKey.getEncoded();
    	System.out.println("\nBYTE KEY::: " + byte_pubkey);

    	//converting byte to String 
    	String str_key = Base64.getEncoder().encodeToString(byte_pubkey);
    	// String str_key = new String(byte_pubkey,Charset.);
    	return str_key;
    	

    }
    public static PublicKey convertStringtoPublicKey(String publicK) throws Exception{
    	X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(Base64.getDecoder().decode(publicK));
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PublicKey publicKey = keyFactory.generatePublic(pubKeySpec);
        return publicKey;

    }
}
