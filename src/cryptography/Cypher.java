// Xifratge AES
// More info in https://docs.oracle.com/javase/8/docs/api/javax/crypto/Cipher.html

package cryptography;

import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import javax.crypto.*;


public class Cypher
{
	// Protected attributes
	protected String		algorithm = "AES";		// AES/CBC/NoPadding, AES/CBC/PKCS5Padding
	protected int			keyLength = 128;		// 128, 256, 512


	// Cipher variables
	protected Cipher		ci;
	protected KeyGenerator	keyGen;
	protected SecretKey		secretKey;
	
	public Cypher()
	{
		this("AES",128);
	}
	
	public Cypher(String algorithm, int keyLength)
	{
		this.algorithm = algorithm;
		this.keyLength = keyLength;
		
		try {
			// Instantiate algorithm
			ci = Cipher.getInstance(algorithm);

			// Instantiate key generator
			keyGen = KeyGenerator.getInstance(algorithm);
			keyGen.init(keyLength);
			secretKey = keyGen.generateKey();
		} catch (NoSuchAlgorithmException ex) {
			System.err.println("Error: No existe el algortimo " + algorithm);
		} catch (NoSuchPaddingException ex) {
			System.err.println("Error con el algoritmo " + algorithm);
		}
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
}
