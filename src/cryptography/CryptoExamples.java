// Some examples of digest and encryption with 
// MessageDigest and Cipher classes

package cryptography;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.BadPaddingException;

import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

/**
 *
 * @author osanf
 */
public class CryptoExamples
{
	public static void SimpleDigest()
	{
		// Instantiate a SHA-256 MessageDigest object 
		MessageDigest md = null;
		String algorithm = "SHA-256";	// SHA-1, MD5, MD2, ...
		try {
			md = MessageDigest.getInstance("SHA-256");
		}
		catch (NoSuchAlgorithmException ex) {
			System.err.println("Error: No existeix l'algorisme " + algorithm +
					": " + ex);
		}
		
		// Calculate SHA HASH
		if(md != null) {
			md.update("Hola! Sóc una cadena de text".getBytes());
			byte[] hash = md.digest();	// also works 'md.digest(input)' without update.
			String readableHash = CryptoUtils.bytesToHex(hash);
			System.out.println("resum de la cadena: " + readableHash);		
		}
	}
	
	public static void SimpleSimmetricEncryption(boolean cbcMode)
	{
		
		//String		algorithm = "AES/CBC/PKCS5Padding";
		String		algorithm = "AES/" + (cbcMode ? "CBC" : "ECB") + "/PKCS5Padding";
		int			keyLength = 192;
		String		keyAlgorithm = "AES";
		
		// For CBC Mode
		byte[] iv = {0x00, 0x01, 0x02, 0x03
					,0x04, 0x05, 0x06, 0x07
					,0x08, 0x09, 0x0A, 0x0B
					,0x0C, 0x0D, 0x0E, 0x0F};
		
		try {
			// INSTANTIATE CIPHER
			Cipher ci = Cipher.getInstance(algorithm);
			
			// GENERATE SECRET KEY
			// Or set it (see 'Digest.passwordKeyGenerator')
			KeyGenerator keyGen = KeyGenerator.getInstance(keyAlgorithm);
			keyGen.init(keyLength);
			SecretKey secretKey = keyGen.generateKey();
			
			// ENCRYPTING
			// INITIATE CIPHER
			if(cbcMode)	{
				try {
					ci.init(Cipher.ENCRYPT_MODE, secretKey, new IvParameterSpec(iv));
				} catch (InvalidAlgorithmParameterException ex) {
					System.err.println("Error amb els paràmetres del cipher: "
							+ algorithm + "Exception: " + ex);
				}
			} else	ci.init(Cipher.ENCRYPT_MODE, secretKey);
			
			// ENCRYPT A MESSAGE (String)
			String message = "Aquest missatge serà xifrat";
			byte[] encryptedMessage = ci.doFinal(message.getBytes());
			
			// DECRYPTING
			// INITIATE CIPHER
			if(cbcMode)	{
				try {
					ci.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(iv));
				} catch (InvalidAlgorithmParameterException ex) {
					System.err.println("Error amb els paràmetres del cipher: "
							+ algorithm + "Exception: " + ex);
				}
			} else	ci.init(Cipher.DECRYPT_MODE, secretKey);
			
			// DECRYPT THE MESSAGE (String)
			byte[] decryptedMessage = ci.doFinal(encryptedMessage);
		
			
			System.out.println("Xifratge text '+" + message + "':"
					+ new String(encryptedMessage));
			System.out.println("Desxifratge text '+" + new String(encryptedMessage)
					+ "':" + new String(decryptedMessage));
			
			
		// Exceptions of Cipher.getInstance and KeyGenerator
		} catch (NoSuchAlgorithmException ex) {
		System.err.println("Error: No existeix l'algorisme: "
				+ algorithm + "Exception: " + ex);
		} catch (NoSuchPaddingException ex) {
		System.err.println("Error amb l'algorisme: "
				+ algorithm + "Exception: " + ex);
		// Exceptions of Cipher.init
		} catch (InvalidKeyException ex) {
			System.err.println("Error amb la clau privada: " + ex);
		// Exceptions of Cipher.doFinal
		} catch (IllegalBlockSizeException ex) {
			System.err.println("Error amb el tamany del bloc de l'algorisme: "
					+ algorithm + "Exception: " + ex);
		} catch (BadPaddingException ex) {
			System.err.println("Error amb el farciment (padding) del bloc de l'algorisme: "
					+ algorithm + "Exception: " + ex);
		}
	}
}
