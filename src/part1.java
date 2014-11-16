// Authors:
// Rohan Parikh, Neelang Naval
// This code is part of our security class computer project 


import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.SerpentEngine;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.BufferedWriter;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Random;

public class part1 {
	
	// Static method to encrypt with AES
	public static double encryptWithAES(int keysize, String mode, String plaintext){
		double start = 0;
		double stop = 0;
		try {
			// the initializtion vector
			byte[] IV = new byte[16];		 
	    	new Random().nextBytes(IV);
	    	IvParameterSpec ivspec = new IvParameterSpec(IV);
	    	Cipher c;								
	    	KeyGenerator keyGen = null;
			// AES with mode and padding scheme ?
			c = Cipher.getInstance("AES/"+mode+"/PKCS5Padding");
			keyGen = KeyGenerator.getInstance("AES");
			keyGen.init(keysize); 
	    	SecretKey secretKey = keyGen.generateKey();
	    	// Initializing to encrypt
	    	c.init(Cipher.ENCRYPT_MODE,secretKey, ivspec);
	    	// Getting the plain text bytes
	    	start = System.nanoTime();
	        byte[] cipherTextAES = c.doFinal(plaintext.getBytes());
	        stop = System.nanoTime();
	        //System.out.println(decodedText);
		} catch (NoSuchAlgorithmException  e) {
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (InvalidAlgorithmParameterException e) {
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			e.printStackTrace();
		} catch (BadPaddingException e) {
			e.printStackTrace();
		} 
		
		return (stop - start);
	}
	
	
	// Static method to encrypt with RSA
	public static double encryptWithRSA(int keysize, String plaintext){
		double start = 0;
		double stop = 0;
		// RSA Encryption
    	Cipher c;
		try {
			c = Cipher.getInstance("RSA");
			KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
			// Generating public and private key pair
	    	kpg.initialize(keysize);
	    	KeyPair kp = kpg.genKeyPair();
	    	Key publicKey = kp.getPublic();
	    	Key privateKey = kp.getPrivate();
	    	c.init(Cipher.ENCRYPT_MODE, publicKey);
	    	start = System.nanoTime();
	    	// Encrypting the plain text
	    	byte[] cipherTextRSA = c.doFinal(plaintext.getBytes());
	    	stop = System.nanoTime();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			e.printStackTrace();
		} catch (BadPaddingException e) {
			e.printStackTrace();
		} 
    	return (stop - start);
    	
		
	}
	
	// Static method to encrypt with Serpent
	// www.bouncycastle.org
	public static double encrytWithSerpent(int keysize, String plaintext) throws UnsupportedEncodingException{
		double start = 0;
		double stop = 0;
		
		Security.addProvider(new BouncyCastleProvider());
		int blockSize = 16;
		byte[] IV = new byte[blockSize];
		byte[] key = new byte[keysize/8];
		byte[] pt = new byte[plaintext.getBytes().length];
		byte[] ct = new byte[plaintext.getBytes().length];
		new Random().nextBytes(key);
		new Random().nextBytes(IV);
		PaddedBufferedBlockCipher c = new PaddedBufferedBlockCipher( new CBCBlockCipher(new SerpentEngine()));
		ParametersWithIV parameterIV = new ParametersWithIV(new KeyParameter(key),IV);
		c.init(true, parameterIV);
		pt = plaintext.getBytes();
		try {
			start = System.nanoTime();
			c.processBytes(pt, 0, pt.length, ct, 0);
			c.doFinal(ct, 0);
			stop = System.nanoTime();
		} catch (DataLengthException e) {
			e.printStackTrace();
		} catch (IllegalStateException e) {
			e.printStackTrace();
		} catch (InvalidCipherTextException e) {
			e.printStackTrace();
		}
		
		return (stop -start);
	}
	
	
	// Static method to encrypt with Speck
	// We have used the Speck Engine provided by bouncy castle library
	// www.bouncycastle.org
	public static double encryptWithSpeck(int keySize, int blockSize, String plaintext) throws UnsupportedEncodingException{
		double start = 0;
		double stop = 0;
		
		byte[] IV = new byte[8];
		byte[] key = new byte[keySize/8];
		byte[] pt = new byte[plaintext.getBytes().length];
		byte[] ct = new byte[plaintext.getBytes().length];
		new Random().nextBytes(key);
		new Random().nextBytes(IV);
		PaddedBufferedBlockCipher c = new PaddedBufferedBlockCipher( new CBCBlockCipher(new SpeckEngine(blockSize)));
		ParametersWithIV parameterIV = new ParametersWithIV(new KeyParameter(key),IV);
		c.init(true, parameterIV);
		pt = plaintext.getBytes();
		try {
			start = System.nanoTime();
			c.processBytes(pt, 0, pt.length, ct, 0);
			c.doFinal(ct, 0);
			stop = System.nanoTime();
		} catch (DataLengthException e) {
			e.printStackTrace();
		} catch (IllegalStateException e) {
			e.printStackTrace();
		} catch (InvalidCipherTextException e) {
			e.printStackTrace();
		}
		return (stop -start);
	}
	
	
	// Static method to encrypt with Simon
	// We have used Simon Engine provided by Bouncy Castle library
	// www.bouncycastle.org
	public static double encryptWithSimon(int keySize, int blockSize, String plaintext) throws UnsupportedEncodingException{
		double start = 0;
		double stop = 0;
		
		byte[] IV = new byte[8];
		byte[] key = new byte[keySize/8];
		byte[] pt = new byte[plaintext.getBytes().length];
		byte[] ct = new byte[plaintext.getBytes().length];
		new Random().nextBytes(key);
		new Random().nextBytes(IV);
		PaddedBufferedBlockCipher c = new PaddedBufferedBlockCipher( new CBCBlockCipher(new SimonEngine(blockSize)));
		ParametersWithIV parameterIV = new ParametersWithIV(new KeyParameter(key),IV);
		c.init(true, parameterIV);
		pt = plaintext.getBytes();
		try {
			start = System.nanoTime();
			c.processBytes(pt, 0, pt.length, ct, 0);
			c.doFinal(ct, 0);
			stop = System.nanoTime();
		} catch (DataLengthException e) {
			e.printStackTrace();
		} catch (IllegalStateException e) {
			e.printStackTrace();
		} catch (InvalidCipherTextException e) {
			e.printStackTrace();
		}
		return (stop -start);
	}

   
    public static void main(String...args) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, IOException, InvalidAlgorithmParameterException, InvalidKeySpecException{
    	
        int[] keySizeAES = {128, 192, 256};
        int[] keySizeRSA = {1024, 2048, 4096};
        int[] keySizeSerpent = {128, 192, 256};
        // Same key sizes for simon and speck
        int[] keySizeSpeck32 = {64};
        int[] keySizeSpeck48 = {72, 96};
        int[] keySizeSpeck64 = {96, 128};
        int[] keySizeSpeck96 = {96, 144};
        int[] keySizeSpeck128 = {128,192, 256};
        String mode = "CBC";
        byte[] pt = new byte[1024*100]; 
        new Random().nextBytes(pt);
        
        BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(new FileOutputStream("output.txt"), "utf-8"));
        
        ArrayList<Double> store = new ArrayList<Double>();
        for(int i=0; i<keySizeAES.length; i++){
        	writer.write("Key size is :"+keySizeAES[i]+"\n");
        	for(int j=0; j<100; j++){
        		store.add(part1.encryptWithAES(keySizeAES[i], mode, pt.toString()));
        	}
        	double avg=0;
        	for(int k=0; k<store.size(); k++){
            	writer.write("Time for "+k+"th iteration is :"+store.get(k)+"\n");
            	avg = (avg + store.get(k))/2;
            }
        	store.clear();
        	writer.write("Average time is "+avg);
        	writer.write("\n");
        }
        System.out.println("Done with AES!");
        for(int i=0; i<keySizeRSA.length; i++){
        	writer.write("Key size is :"+keySizeRSA[i]+"\n");
        	for(int j=0; j<100; j++){
        		store.add(part1.encryptWithRSA(keySizeRSA[i], pt.toString()));
        	}
        	System.out.println("Done with RSA"+keySizeRSA[i]+"!");
        	double avg=0;
        	for(int k=0; k<store.size(); k++){
            	writer.write("Time for "+k+"th iteration is :"+store.get(k)+"\n");
            	avg = (avg + store.get(k))/2;
            }
        	store.clear();
        	writer.write("Average time is "+avg);
        	writer.write("\n");
        }

       writer.close();

    	
    }
}
