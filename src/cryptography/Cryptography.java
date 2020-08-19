package cryptography;

import java.io.File;
import java.io.IOException;

public class Cryptography
{
	public static void main(String[] args)
	{
		// SIMPLE EXAMPLES
//		CryptoExamples.SimpleDigest();
//		CryptoExamples.SimpleSimmetricEncryption(true);
//		CryptoExamples.SimpleAsymmetricEncryption();
//		CryptoExamples.SimpleAsymmetricEncryptionWithWrappedKey();
//		CryptoExamples.simpleSignature();
		
		CryptoExamples.storageManagement();
		
		// SIMMETRIC CYPHER WRAPPER EXAMPLES
//		String secretKey = "Contrasenya1#";
//		
//		testCipher("AES/CBC/PKCS5Padding", 256, "AES");
		
		// Other algoritms
		// Xifratge DES. En realitat la clau té 64 bits, encara que demana 56
		//~testCipher("DES/CBC/PKCS5Padding", 56, "DES");
		//~testCipher("DES/CBC/PKCS5Padding", 64, "DES", secretKey);
		
		// Xifratge T-DES. En realitat la clau té 192 bits, encara que demana 168
		//~testCipher("DESede/CBC/PKCS5Padding", 168, "DESede");
		//~testCipher("DESede/CBC/PKCS5Padding", 192, "DESede", secretKey);
	}

	public static void testDigest()
	{	
		try {
			// ####################### EXEMPLES DE RESUM #######################
			// Resum d'una cadena de text
			System.out.println("Resum de la cadena \"Text a resumir\": " +
					(new Digest("SHA-1")).doHash("Text a resumir"));
			
			// Resum d'un fitxer
			System.out.println("Resum del fitxer \"image.jpg\": " + 
					(new Digest("MD5")).doHash(
						new File("project_files"+File.separator+"image.jpg")));

		} catch (IOException ex) {
			System.err.println("Error d'entrada/sortida: " + ex);
		}
	}
	
	public static void testCipher(String algoritm, int lenghtKey, String algKey, String... secretKey)
	{
		try {
		
			// Instantiate cipher
		Cypher cipher = new Cypher(algoritm, secretKey.length > 0? secretKey[0] : null, lenghtKey,algKey);
			// Only for CBC mode: set an IV vector
		byte[] iv = cipher.generateIV();	
			// or cipher.setIV("1234567890ABCDEF".getBytes());
		
		// Xifratge i desxifratge d'una cadena de text
		String input = "Text a xifrar";
		
		// Xifrar
		byte[] encodedInput = cipher.encodeString(input);
		
		System.out.println("Xifrar la cadena de text: \""+input+"\": "
					+ new String(encodedInput));
		
		// Desxifrar
		String decryptedInput = cipher.decodeString(encodedInput);
		System.out.println("Desxifrar la cadena de text \""+input+"\": "
					+ decryptedInput);
			
		// Xifratge i desxifratge d'un fitxer
		cipher.encode(new File("project_files"+File.separator+"image.jpg")
				, new File("project_files"+File.separator+"encoded_image.jpg"));

		cipher.decode(new File("project_files"+File.separator+"encoded_image.jpg")
				, new File("project_files"+File.separator+"decoded_image.jpg"));
		
		
		// Xifratge i desxifratge d'un fitxer amb Cipher Streams
		cipher.encodeStream(new File("project_files"+File.separator+"image.jpg")
				, new File("project_files"+File.separator+"encoded_image.jpg"));

		cipher.decodeStream(new File("project_files"+File.separator+"encoded_image.jpg")
				, new File("project_files"+File.separator+"decoded_image.jpg"));
		
		} catch (IOException ex) {
			System.err.println("Error d'entrada/sortida: " + ex);
		}
	}
}