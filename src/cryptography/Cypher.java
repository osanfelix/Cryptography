/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package cryptography;
import java.security.*;
import javax.crypto.*;

// Xifratge AES
// More info in https://docs.oracle.com/javase/8/docs/api/javax/crypto/Cipher.html
public class Cypher
{
	// Singleton instance
	protected static Cypher	_instance = null;
	protected static String	_algorithm = "AES";	// AES/CBC/NoPadding, AES/CBC/PKCS5Padding
	protected static int	_keyLength = 128;

	
	// Cipher variables
	protected Cipher		ci;
	protected KeyGenerator	keyGen;
	protected SecretKey		secretKey;

	//Static auxiliary representations variables
	final protected static char[] hexArray = "0123456789ABCDEF".toCharArray();

	public static Cypher getInstance() {
		if (_instance == null) {
			_instance = new Cypher();
		}
		return _instance;
	}
	
	protected Cypher()
	{
		try {
			ci = Cipher.getInstance(_algorithm);
			keyGen = KeyGenerator.getInstance(_algorithm);
			keyGen.init(_keyLength);
			secretKey = keyGen.generateKey();
		} catch (NoSuchAlgorithmException ex) {
			System.err.println("Error: No existe el algortimo " + _algorithm);
		} catch (NoSuchPaddingException ex) {
			System.err.println("Error con el algortimo " + _algorithm);
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
			System.err.println("Error en el tamaño de bloque del algortimo " + _algorithm);
		} catch (BadPaddingException ex) {
			System.err.println("Error en el relleno de bloque del algortimo" + _algorithm);
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
			System.err.println("Error en el tamaño de bloque del algortimo " + _algorithm);
		} catch (BadPaddingException ex) {
			System.err.println("Error en el relleno de bloque del algortimo" + _algorithm);
		}
			return null;
	}
	
	public String encodeString(String msg)		// Xifrar
	{
		return new String(encode(msg.getBytes()));
	}
	
	public String decodeString(byte[] msg)		// desxifrar
	{
		return new String(decode(msg));
	}
	
}

