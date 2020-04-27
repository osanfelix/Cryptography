
package cryptography;

//import java.util.Arrays;

import java.io.File;
import java.io.IOException;



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
			// Xifratge i desxifratge d'una cadena de text
			Cypher AESCipher = new Cypher("AES", 128);
			String input = "Text a xifrar";
			// Strings
			System.out.println("Xifrar la cadena de text \""+input+"\": "
					+ AESCipher.encodeString("Text a xifrar"));
			System.out.println("Desxifrar la cadena de text \""+input+"\": "
					+ AESCipher.decodeString(
							AESCipher.encode("Text a xifrar".getBytes())));
			
			// Bytes
//		System.out.println(Arrays.toString("Texto a cifrar".getBytes()));
//		System.out.println(Arrays.toString(AESCipher.encode("Texto a cifrar".getBytes())));
//		System.out.println(Arrays.toString(AESCipher.decode(AESCipher.encode("Texto a cifrar".getBytes()))));
		} catch (IOException ex) {
			System.err.println("Error d'entrada/sortida: " + ex);
		}
		
}

}
