// MessageDigest 'Wrapper'. More info in:
// https://docs.oracle.com/javase/8/docs/api/java/security/MessageDigest.html

// Get Bytes help:
// https://docs.oracle.com/javase/8/docs/api/java/lang/String.html#getBytes-java.nio.charset.Charset


package cryptography;


import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import java.io.File;						// Files
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
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
		return md.digest();	// also works 'md.digest(input)' without update.
	}
	
	public String doHash(String text)
	{
		md.update(text.getBytes(StandardCharsets.UTF_8));
		//md.update(text.getBytes("UTF-8"));	// required try-catch/finally
		//md.update(text.getBytes());			// Not recomended
		
		byte[] hashByte = md.digest();
		
		return CryptoUtils.bytesToHex(hashByte);
	}
	
	public String doHash(File route) throws IOException 
	{
		// Since Java SE 7 you can avoid finally block.
		// FileInputStream implements Java.lang.AutoCloseable
		try(InputStream in = new FileInputStream(route)) {
			
			if(route.isFile()) {
				//Create byte array to read data in chunks
				byte[] byteArray = new byte[1024];
				int bytesCount = 0; 

				while((bytesCount = in.read(byteArray))!= -1){
					md.update(byteArray, 0, bytesCount);	
				}
				
				return CryptoUtils.bytesToHex(md.digest());
			}
		}
		return null;
	}
	
	// Generate a key from String
	public SecretKey passwordKeyGenerator(String text, int keySize, String algoritm)
	{
		if (keySize%8 == 0)
		{
			try
			{
				byte[] hashByte = doHash(text.getBytes());
				return new SecretKeySpec(Arrays.copyOf(hashByte, keySize/8), algoritm);
			} catch (Exception ex) {
				System.err.println("Error generant la clau:" + ex);
			}
		}
		System.err.println("Error: Longitud clau no multiple de 8.");
		return null;
	}
}