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
			} else {
				secretKey = this.convertKey(key, keyLength, keyAlgorithm);
			}
			
			this.algorithm = algorithm;
			this.keyLength = keyLength;

			// Instantiate algorithm
			ci = Cipher.getInstance(algorithm);
			
		} catch (NoSuchAlgorithmException ex) {
			System.err.println("Error: No existeix l'algorisme " + algorithm);
		} catch (NoSuchPaddingException ex) {
			System.err.println("Error amb l'algorisme " + algorithm);
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
			
			return encodedText;
		} catch (InvalidKeyException ex) {
			System.err.println("Error la clave privada utilizada " + secretKey.toString());
		} catch (IllegalBlockSizeException ex) {
			System.err.println("Error en el tamaño de bloque del algortimo " + algorithm);
		} catch (BadPaddingException ex) {
			System.err.println("Error en el relleno de bloque del algortimo" + algorithm);
		}
		return null;
	}
	
	public byte[] decode(byte[] encodedText)		// Desxifrar
	{
		byte[] decodedText = null;
		try {
			ci.init(Cipher.DECRYPT_MODE, secretKey);
			decodedText = ci.doFinal(encodedText);

			return decodedText;
		} catch (InvalidKeyException ex) {
			System.err.println("Error la clave privada utilizada " + secretKey.toString());
		} catch (IllegalBlockSizeException ex) {
			System.err.println("Error en el tamaño de bloque del algortimo " + algorithm);
		} catch (BadPaddingException ex) {
			System.err.println("Error en el relleno de bloque del algortimo" + algorithm);
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
	
	// TODO
	public File encode(File fileIn, File fileOut) throws IOException, ShortBufferException 		// Xifrar
	{
		try(InputStream in = new FileInputStream(fileIn);OutputStream out = new FileOutputStream(fileOut) ) {
			byte[] byteArray = new byte[1024];
			byte[] outBytes = new byte[4096];
			int outCount = 0;
			int bytesCount = 0;
			
			ci.init(Cipher.ENCRYPT_MODE, secretKey);
			
			// DO NOT WORK
//			while((bytesCount = in.read(byteArray)) != -1) {
//				ci.update(byteArray, 0, bytesCount, outBytes, outCount);
//				outCount += bytesCount;
//			}
//			outCount += ci.doFinal(outBytes, outCount);
//			out.write(outBytes, 0, outCount);
//			out.close();


			while((bytesCount = in.read(byteArray)) != -1) {
				out.write(ci.update(byteArray, 0, bytesCount));
				
			}
			out.write(ci.doFinal());
			out.close();
		
		} catch (InvalidKeyException ex) {
			System.err.println("Error la clave privada utilizada " + secretKey.toString());
		} catch (IllegalBlockSizeException ex) {
			System.err.println("Error en el tamaño de bloque del algortimo " + algorithm);
		} catch (BadPaddingException ex) {
			System.err.println("Error en el relleno de bloque del algortimo" + algorithm);
		}
		
		return null;
	}
	
	// TODO
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
			out.close();
		} catch (InvalidKeyException ex) {
			System.err.println("Error la clave privada utilizada " + secretKey.toString());
		} catch (IllegalBlockSizeException ex) {
			System.err.println("Error en el tamaño de bloque del algortimo " + algorithm);
		} catch (BadPaddingException ex) {
			System.err.println("Error en el relleno de bloque del algortimo" + algorithm);
		}
		
		return null;
	}
	
}
