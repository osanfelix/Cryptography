
package cryptography;

import java.util.Arrays;


public class Cryptography
{
	public static void main(String[] args)
	{
		// Resumen de una cadena de texto
		System.out.println((Digest.getInstance()).doHash("Texto a resumir"));
		
		// Cifrado y descifrado de una cadena de texto
		// Strings
		System.out.println((Cypher.getInstance()).encodeString("Texto a cifrar"));
		System.out.println(Cypher.getInstance().decodeString(Cypher.getInstance().encode("Texto a cifrar".getBytes())));
		
		// Bytes
		System.out.println(Arrays.toString("Texto a cifrar".getBytes()));
		System.out.println(Arrays.toString((Cypher.getInstance()).encode("Texto a cifrar".getBytes())));
		System.out.println(Arrays.toString((Cypher.getInstance()).decode((Cypher.getInstance()).encode("Texto a cifrar".getBytes()))));
	}

}
