/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package cryptography;

import java.io.File;
import java.security.*;

// MessageDigest 'Wrapper'
// Info in https://docs.oracle.com/javase/8/docs/api/java/security/MessageDigest.html
public class Digest
{
	// Singleton instance
	protected static Digest _instance = null;
	
	protected static String _algorithm = "SHA-256";
	
	// MessageDigest variable
	protected MessageDigest md;
	

	public static Digest getInstance()
	{
	if(_instance == null)
		_instance = new Digest();
			return _instance;       
	}

	protected Digest()
	{
		try {
			md = MessageDigest.getInstance(_algorithm);
		}
		catch (NoSuchAlgorithmException ex) {
			System.err.println("Error: No existe el algortimo " + _algorithm);
		}
	}
	
	public String doHash(String text)
	{
		md.update(text.getBytes());
		byte[] hashByte = md.digest();
		
		return CryptoUtils.bytesToHex(hashByte);
	}
	
	public String doHash(File route)
	{
		// TODO
		return null;
	}
}

