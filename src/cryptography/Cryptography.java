package cryptography;

import java.io.File;
import java.io.IOException;
import javax.crypto.ShortBufferException;


public class Cryptography
{
	public static void main(String[] args)
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
			
			
// ###################### EXEMPLES DE XIFRAT #######################
			// Xifratge AES
			Cypher AESCipher = new Cypher("AES","contrsenya1", 256,"AES");

			// Xifratge DES. En realitat la clau té 64 bits, encara que demana 56
			Cypher DESCipher = new Cypher("DES/ECB/PKCS5Padding",null, 56 , "DES");
			//Cypher DESCipher = new Cypher("DES","contrasenya1", 64 , "DES");
			
			// Xifratge T-DES. En realitat la clau té 192 bits, encara que demana 168
			Cypher TDESAESCipher = new Cypher("DESede",null, 168 , "DESede");
			//Cypher AESCipher = new Cypher("DESede/ECB/PKCS5Padding","contrasenya1", 192 , "DESede");
			
			
			// Xifratge i desxifratge d'una cadena de text
			String input = "Text a xifrar";
			

			System.out.println("Xifrar la cadena de text \""+input+"\": "
					+ AESCipher.encodeString("Text a xifrar"));
			
			System.out.println("Desxifrar la cadena de text \""+input+"\": "
					+ AESCipher.decodeString(
							AESCipher.encode("Text a xifrar".getBytes())));
			
			// Xifratge i desxifratge d'un fitxer
			Cypher AESCipherStream = new Cypher("AES","contrsenya1", 256,"AES");
			AESCipherStream.encode(new File("project_files"+File.separator+"image.jpg")
					, new File("project_files"+File.separator+"encoded_image.jpg"));
			
			AESCipherStream.decode(new File("project_files"+File.separator+"encoded_image.jpg")
					, new File("project_files"+File.separator+"decoded_image.jpg"));

		} catch (IOException ex) {
			System.err.println("Error d'entrada/sortida: " + ex);
		} catch (ShortBufferException ex) {
			System.err.println("Error de buffer: " + ex);
		}
		
}

}
