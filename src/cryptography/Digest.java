// MessageDigest 'Wrapper'. More info in:
// https://docs.oracle.com/javase/8/docs/api/java/security/MessageDigest.html

// Get Bytes help:
// https://docs.oracle.com/javase/8/docs/api/java/lang/String.html#getBytes-java.nio.charset.Charset-

package cryptography;


import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import java.io.File;						// Files
import java.nio.charset.StandardCharsets;	// String.getBytes

import java.util.Arrays;
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;

public class Digest
{
	protected String algorithm = "SHA-256"; // Other options are: MD2, MD5, MD5,
											// SHA-1, SHA-224, SHA-256, SHA-384
											// SHA-512
	// MessageDigest variable
	protected MessageDigest md;
	
	public Digest(String algorithm)
	{
		this.algorithm = algorithm;
		
		try {
			md = MessageDigest.getInstance(algorithm);
		}
		catch (NoSuchAlgorithmException ex) {
			System.err.println("Error: No existeix l'algorisme " + algorithm +
					": " + ex);
		}
	}
	
	public byte[] doHash(byte[] input)
	{
		md.update(input);
		return md.digest();
	}
	
	public String doHash(String text)
	{
		
		md.update(text.getBytes(StandardCharsets.UTF_8));
		//md.update(text.getBytes("UTF-8")); // required try-catch
		//md.update(text.getBytes());	// Not recomended
		
		byte[] hashByte = md.digest();
		
		return CryptoUtils.bytesToHex(hashByte);
	}
	
	public String doHash(File route)
	{
		// TODO
		return null;
	}
	
	// Generate a key from String
	public SecretKey passwordKeyGenerator(String text, int keySize)
	{
		if ((keySize == 128)||(keySize == 192)||(keySize == 256))
		{
			try
			{
				byte[] hashByte = doHash(text.getBytes());
				return new SecretKeySpec(Arrays.copyOf(hashByte, keySize/8), "AES");
			} catch (Exception ex) {
				System.err.println("Error generant la clau:" + ex);
			}
		}
		return null;
	}
}

