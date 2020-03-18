
package cryptography;

//import java.util.Arrays;


public class Cryptography
{
	public static void main(String[] args)
	{
		// Resum d'una cadena de text
		System.out.println((new Digest("SHA-1")).doHash("Text a resumir"));
		
		// Xifratge i desxifratge d'una cadena de text
		Cypher AESCipher = new Cypher("AES", 128);
		String input = "Text a xifrar";
			// Strings
		System.out.println("Xifrar la cadena de text \""+input+"\": "
				+ AESCipher.encodeString("Text a xifrar"));
		System.out.println("Desxifrar la cadena de text \""+input+"\": "
				+ AESCipher.decodeString(AESCipher.encode("Text a xifrar".getBytes())));
		
			// Bytes
//		System.out.println(Arrays.toString("Texto a cifrar".getBytes()));
//		System.out.println(Arrays.toString(AESCipher.encode("Texto a cifrar".getBytes())));
//		System.out.println(Arrays.toString(AESCipher.decode(AESCipher.encode("Texto a cifrar".getBytes()))));
		
}

}
