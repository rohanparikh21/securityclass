import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;

public class part1 {
	
	
	public static void encryptWithAES(int keysize, String mode, String plaintext){
		// AES Encryption
		// Initialization vector for AES
    	byte[] iv = { 0, 0, 0, 0, 0, 0, 0, 0,0, 0, 0, 0,0, 0, 0, 0};
    	IvParameterSpec ivspec = new IvParameterSpec(iv);
    	Cipher c;
    	// Symmetric key generator
    	KeyGenerator keyGen = null;
		try {
			// AES with mode and padding scheme ?
			c = Cipher.getInstance("AES/"+mode+"/PKCS5Padding");
			keyGen = KeyGenerator.getInstance("AES");
			keyGen.init(keysize); 
	    	SecretKey secretKey = keyGen.generateKey();
	    	// Initializing to encrypt
	    	c.init(Cipher.ENCRYPT_MODE,secretKey, ivspec);
	    	// Getting the plain text bytes
	    	double start = System.nanoTime();
	        byte[] cipherTextAES = c.doFinal(plaintext.getBytes());
	        double stop = System.nanoTime();
	        System.out.println("Time taken is: "+ (stop - start));
	        String  cipherText = new String(cipherTextAES, "UTF-8");
	        //System.out.println(cipherText);
	        // Initializing for decryption
	        c.init(Cipher.DECRYPT_MODE, secretKey, ivspec);
	        byte[] decipheredText = c.doFinal(cipherTextAES);
	        String decodedText = new String(decipheredText, "UTF-8");
	        //System.out.println(decodedText);
		} catch (NoSuchAlgorithmException  e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidAlgorithmParameterException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (UnsupportedEncodingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (BadPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} 
	}
	
	public static void encryptWithRSA(int keysize, String plaintext){
		
		// RSA Encryption
    	Cipher c1;
		try {
			c1 = Cipher.getInstance("RSA");
			KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
	    	kpg.initialize(keysize);
	    	KeyPair kp = kpg.genKeyPair();
	    	Key publicKey = kp.getPublic();
	    	Key privateKey = kp.getPrivate();
	    	KeyFactory fact = KeyFactory.getInstance("RSA");
	    	RSAPublicKeySpec pub = fact.getKeySpec(kp.getPublic(), RSAPublicKeySpec.class);
	    	RSAPrivateKeySpec priv = fact.getKeySpec(kp.getPrivate(), RSAPrivateKeySpec.class);
	    	//System.out.println(priv.getPrivateExponent());
	    	c1.init(Cipher.ENCRYPT_MODE, publicKey);
	    	double start = System.nanoTime();
	    	byte[] cipherTextRSA = c1.doFinal(plaintext.getBytes());
	    	double stop = System.nanoTime();
	    	System.out.println("Time taken is: "+ (stop - start));
	    	String encodedRSACipher = new String(cipherTextRSA, "UTF-8");
	        //System.out.println(encodedRSACipher);
	        c1.init(Cipher.DECRYPT_MODE, privateKey);
	        double start1 = System.nanoTime();
	        byte[] decipherTextRSA = c1.doFinal(cipherTextRSA);
	        double stop1 = System.nanoTime();
	    	System.out.println("Time taken for decryption is: "+ (stop1 - start1));
	        String decodedRSACipher = new String(decipherTextRSA, "UTF-8");
	        //System.out.println(decodedRSACipher);
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeySpecException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (BadPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (UnsupportedEncodingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
    	
    	
		
	}

   
    public static void main(String...args) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, IOException, InvalidAlgorithmParameterException, InvalidKeySpecException{
    	
        int[] keysizeAES = {1024, 2048};
    	String text = "This is plaintext";
    	for(int j=0; j< 100; j++){
    		System.out.println("Loop iteration :"+j);
    	for(int i=0; i < keysizeAES.length; i++){
    		part1.encryptWithRSA(keysizeAES[i], text);
    	}
    	}
    }
}
