// Xifratge AES
// More info in https://docs.oracle.com/javase/8/docs/api/javax/crypto/Cipher.html
// https://docs.oracle.com/javase/8/docs/technotes/guides/security/SunProviders.html#SunJCEProvider
// Garceta 269 DELETE

package cryptography;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import javax.crypto.*;


public class Cypher
{
	// Protected attributes
	protected String		algorithm = null;	// AES, DES
												// AES/ECB/PKCS5Padding 
												// AES/CBC/NoPadding, 
												// Key Algorithms: AES, DES

	protected int			keyLength = -1;		// Ex: 56, 128, 192, 256, 512
	

	// Cipher variables
	protected Cipher		ci;
	protected KeyGenerator	keyGen;
	protected SecretKey		secretKey;
	
	public Cypher()
	{
		this("AES",128,"AES");
	}
	
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
		}
	}
	
	public Cypher(String algorithm, int keyLength, String keyAlgorithm)
	{
		this(algorithm, null, keyLength, keyAlgorithm);
	}
	
	public final SecretKey convertKey(String key, int keyLength, String keyAlgorithm)
	{
		// Convert String to valid SecretKey
		Digest keyHash = new Digest("SHA-1");
		return keyHash.passwordKeyGenerator(key, keyLength, keyAlgorithm);
	}
	
	public byte[] encode(byte[] msg)		// Xifrar
	{
		byte[] encodedText = null;
		try {
			ci.init(Cipher.ENCRYPT_MODE, secretKey);
			encodedText = ci.doFinal(msg);
			
		} catch (InvalidKeyException ex) {
			System.err.println("Error amb la clau privada: "
					+ secretKey.toString() + "Exception: " + ex);
		} catch (IllegalBlockSizeException ex) {
			System.err.println("Error amb el tamany del bloc de l'algorisme: "
					+ algorithm + "Exception: " + ex);
		} catch (BadPaddingException ex) {
			System.err.println("Error amb el farciment (padding) del bloc de l'algorisme: "
					+ algorithm + "Exception: " + ex);
		}
		return encodedText;
	}
	
	public byte[] decode(byte[] encodedText)		// Desxifrar
	{
		byte[] decodedText = null;
		try {
			ci.init(Cipher.DECRYPT_MODE, secretKey);
			decodedText = ci.doFinal(encodedText);

			return decodedText;
		} catch (InvalidKeyException ex) {
			System.err.println("Error amb la clau privada: "
					+ secretKey.toString() + "Exception: " + ex);
		} catch (IllegalBlockSizeException ex) {
			System.err.println("Error amb el tamany del bloc de l'algorisme: "
					+ algorithm + "Exception: " + ex);
		} catch (BadPaddingException ex) {
			System.err.println("Error amb el farciment (padding) del bloc de l'algorisme: "
					+ algorithm + "Exception: " + ex);
		}
			return null;
	}
	
	// String encode/decode
	public String encodeString(String msg)		// Xifrar
	{
		return new String(encode(msg.getBytes(StandardCharsets.UTF_8)));
	}
	
	public String decodeString(byte[] msg)		// desxifrar
	{
		return new String(decode(msg));
	}
	
	
	public void encode(File fileIn, File fileOut) throws IOException, ShortBufferException 		// Xifrar
	{
		try(InputStream in = new FileInputStream(fileIn);OutputStream out = new FileOutputStream(fileOut) ) {
			byte[] byteArray = new byte[1024];
			int bytesCount = 0;
			
			ci.init(Cipher.ENCRYPT_MODE, secretKey);

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
		}
	}
	
	public File decode(File fileIn, File fileOut) throws IOException, ShortBufferException 		// Desxifrar
	{
		try(InputStream in = new FileInputStream(fileIn);OutputStream out = new FileOutputStream(fileOut) ) {
			byte[] byteArray = new byte[1024];
			int bytesCount = 0;
			
			ci.init(Cipher.DECRYPT_MODE, secretKey);

			while((bytesCount = in.read(byteArray)) != -1) {
				out.write(ci.update(byteArray, 0, bytesCount));
			}
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
		}
		
		return null;
	}
	
	// With CipherInputStream or CipherOutputStream.
	// You can use them for encrypt and decrypt indistinctly.
	public void encodeStream(File fileIn, File fileOut) throws IOException 	// Xifrar
	{
		InputStream in = null;
		OutputStream out = null;
		CipherOutputStream cos = null;
		try	{
			ci.init(Cipher.ENCRYPT_MODE, secretKey);
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
			ci.init(Cipher.DECRYPT_MODE, secretKey);
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
		} finally {
			if (out != null)	out.close();
			if (cis != null)	cis.close();
		}
	}
}
