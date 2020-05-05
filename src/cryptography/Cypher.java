// Chiper 'Wrapper'. More info in:
// More info in https://docs.oracle.com/javase/8/docs/api/javax/crypto/Cipher.html

// https://docs.oracle.com/javase/8/docs/technotes/guides/security/SunProviders.html#SunJCEProvider

// Garceta 269 DELETE

package cryptography;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;


public class Cypher
{
	// Protected attributes
	protected String		algorithm = null;	// AES, DES
												// AES/ECB/PKCS5Padding 
												// AES/CBC/NoPadding, 
												// Key Algorithms: AES, DES
	final String mode;							// ECB, CBC

	protected int			keyLength = -1;		// Ex: 56, 128, 192, 256, 512
	protected byte[] iv;						// For 'CBC' mode

	// Cipher variables
	protected Cipher		ci;
	protected KeyGenerator	keyGen;
	protected SecretKey		secretKey;
	

	public Cypher(String algorithm, String key, int keyLength, String keyAlgorithm)
	{
		try {
			if(key == null) {	// Generate a key
				keyGen = KeyGenerator.getInstance(keyAlgorithm);
				keyGen.init(keyLength);
				secretKey = keyGen.generateKey();
				
			} else {			// Use the digest of a string
				secretKey = this.convertKey(key, keyLength, keyAlgorithm);
			}
			
			this.algorithm = algorithm;
			this.keyLength = keyLength;

			// Instantiate algorithm
			ci = Cipher.getInstance(algorithm);
			
		} catch (NoSuchAlgorithmException ex) {
			System.err.println("Error: No existeix l'algorisme: "
					+ algorithm + "Exception: " + ex);
		} catch (NoSuchPaddingException ex) {
			System.err.println("Error amb l'algorisme: "
					+ algorithm + "Exception: " + ex);
		} finally {
			if(algorithm.contains("/"))
				mode = algorithm.split("/")[1];
			else	mode = "ECB";
		}
	}
	
	public Cypher(String algorithm, int keyLength, String keyAlgorithm)
	{
		this(algorithm, null, keyLength, keyAlgorithm);
	}
	
	// action = Cipher.ENCRYPT_MODE or Cipher.DECRYPT_MODE
	public void initCypher(int action) throws InvalidKeyException,
									InvalidAlgorithmParameterException	
	{
		if(this.mode.equals("CBC")) {
			ci.init(action, secretKey, new IvParameterSpec(iv));
		} else
			ci.init(action, secretKey);
		
	}
		
	public byte[] generateIV() {
		iv = new byte[ci.getBlockSize()];
		SecureRandom byteRandomizer = new SecureRandom();
		byteRandomizer.nextBytes(iv);
		return iv;
	}
	
	public void setIV(byte[] ivector)
	{
		iv = ivector;
	}
	
	public final SecretKey convertKey(String key, int keyLength, String keyAlgorithm)
	{
		// Convert String to valid SecretKey
		Digest keyHash = new Digest("SHA-1");
		return keyHash.passwordKeyGenerator(key, keyLength, keyAlgorithm);
	}
	
	// Encrypts or decrypts.
	public byte[] codec(int action, byte[] msg)
	{
		byte[] codecText = null;
		try {
			initCypher(action);
			codecText = ci.doFinal(msg);
			
		} catch (IllegalBlockSizeException ex) {
			System.err.println("Error amb el tamany del bloc de l'algorisme: "
					+ algorithm + "Exception: " + ex);
		} catch (BadPaddingException ex) {
			System.err.println("Error amb el farciment (padding) del bloc de l'algorisme: "
					+ algorithm + "Exception: " + ex);
		} catch (InvalidKeyException ex) {
			System.err.println("Error amb la clau privada: "
					+ secretKey.toString() + "Exception: " + ex);
		} catch (InvalidAlgorithmParameterException ex) {
			System.err.println("Error amb els paràmetres del cipher: "
					+ algorithm + "Exception: " + ex);
		}
		return codecText;
	}
	public byte[] encode(byte[] msg)		// Xifrar
	{
		return codec(Cipher.ENCRYPT_MODE,msg);
	}
	
	public byte[] decode(byte[] encodedText)		// Desxifrar
	{
		return codec(Cipher.DECRYPT_MODE,encodedText);
	}
	
	// String encode/decode
	public byte[] encodeString(String msg)		// Xifrar
	{
		return codec(Cipher.ENCRYPT_MODE,msg.getBytes(StandardCharsets.UTF_8));
	}
	
	public String decodeString(byte[] msg)		// desxifrar
	{
		return new String(codec(Cipher.DECRYPT_MODE,msg));
	}
	
	
	// Encrypts or decrypts a file
	public void codec(int action, File fileIn, File fileOut) throws IOException
	{
		try(InputStream in = new FileInputStream(fileIn);OutputStream out = new FileOutputStream(fileOut) ) {
			byte[] byteArray = new byte[1024];
			int bytesCount = 0;
			
			initCypher(action);

			while((bytesCount = in.read(byteArray)) != -1)
				out.write(ci.update(byteArray, 0, bytesCount));
				
			out.write(ci.doFinal());
		} catch (InvalidKeyException ex) {
			System.err.println("Error amb la clau privada: "
					+ secretKey.toString() + "Exception: " + ex);
		} catch (IllegalBlockSizeException ex) {
			System.err.println("Error amb el tamany del bloc de l'algorisme: "
					+ algorithm + "Exception: " + ex);
		} catch (BadPaddingException ex) {
			System.err.println("Error amb el farciment (padding) del bloc de l'algorisme: "
					+ algorithm + "Exception: " + ex);
		} catch (InvalidAlgorithmParameterException ex) {
			System.err.println("Error amb els paràmetres del cipher: "
					+ algorithm + "Exception: " + ex);
		}
	}
		
	public void encode(File fileIn, File fileOut) throws IOException	// Xifrar
	{
		codec(Cipher.ENCRYPT_MODE, fileIn, fileOut);
	}
	
	public void decode(File fileIn, File fileOut) throws IOException	// Desxifrar
	{
		codec(Cipher.DECRYPT_MODE, fileIn, fileOut);
	}
	
	// With CipherInputStream or CipherOutputStream.
	// You can use them for encrypt and decrypt indistinctly.
	// Here there's tow examples with input and ouuput cipher stremas
	public void encodeStream(File fileIn, File fileOut) throws IOException 	// Xifrar
	{
		InputStream in = null;
		OutputStream out = null;
		CipherOutputStream cos = null;
		try	{
			initCypher(Cipher.ENCRYPT_MODE);
			in = new FileInputStream(fileIn);
			out = new FileOutputStream(fileOut);
			cos = new CipherOutputStream(out, ci);
			
			byte[] byteArray = new byte[1024];
			int bytesCount = 0;
			
			while((bytesCount = in.read(byteArray)) != -1)
				cos.write(byteArray, 0, bytesCount);
			cos.flush();
			
		} catch (InvalidKeyException ex) {
			System.err.println("Error amb la clau privada: "
					+ secretKey.toString() + "Exception: " + ex);
		} catch (InvalidAlgorithmParameterException ex) {
			System.err.println("Error amb els paràmetres del cipher: "
					+ algorithm + "Exception: " + ex);
		} finally {
			if (in != null)		in.close();
			if (cos != null)	cos.close();	// Here it executes doFinal()
		}
	}
	
	public void decodeStream(File fileIn, File fileOut) throws IOException		// Desxifrar
	{
		InputStream in = null;
		OutputStream out = null;
		CipherInputStream cis = null;
		try	{
			initCypher(Cipher.DECRYPT_MODE);
			in = new FileInputStream(fileIn);
			out = new FileOutputStream(fileOut);
			cis = new CipherInputStream(in, ci);
			
			byte[] byteArray = new byte[1024];
			int bytesCount = 0;
			
			while((bytesCount = cis.read(byteArray)) != -1)
				out.write(byteArray, 0, bytesCount);
			
		} catch (InvalidKeyException ex) {
			System.err.println("Error amb la clau privada: "
					+ secretKey.toString() + "Exception: " + ex);
		} catch (InvalidAlgorithmParameterException ex) {
			System.err.println("Error amb els paràmetres del cipher: "
					+ algorithm + "Exception: " + ex);
		} finally {
			if (out != null)	out.close();
			if (cis != null)	cis.close();
		}
	}
}
