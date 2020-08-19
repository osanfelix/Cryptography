// Some examples of digest and encryption with 
// MessageDigest, Cipher and Signature classes

package cryptography;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.cert.Certificate;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.util.Enumeration;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;


public class CryptoExamples
{
	public static void SimpleDigest()
	{
		// Instantiate a SHA-256 MessageDigest object 
		MessageDigest md = null;
		String algorithm = "SHA-256";	// SHA-1, MD5, MD2, ...
		try {
			md = MessageDigest.getInstance(algorithm);
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
	
	public static void SimpleAsymmetricEncryption()	// RSA
	{
		String		algorithm = "RSA/ECB/PKCS1Padding";
		int			keyLength = 512;	// 1024, 2048
		
		try {
			// INSTANTIATE CIPHER
			Cipher ci = Cipher.getInstance(algorithm);
			
			// GENERATE KEY PAIR
			KeyPair keys = null;

			KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
			//~SecureRandom randomizer = SecureRandom.getInstance("SHA1PRNG");
			//~keyGen.initialize(keyLength, randomizer);
			keyGen.initialize(keyLength);
			keys = keyGen.genKeyPair();

			PrivateKey privateKey = keys.getPrivate();
			PublicKey publicKey = keys.getPublic();
			
			// ENCRYPTING
			// INITIATE CIPHER
			ci.init(Cipher.ENCRYPT_MODE, publicKey);
			
			
			// ENCRYPT A MESSAGE (String)
			String message = "Aquest missatge serà xifrat";
			byte[] encryptedMessage = ci.doFinal(message.getBytes());
			
			// DECRYPTING
			// INITIATE CIPHER
			ci.init(Cipher.DECRYPT_MODE, privateKey);
			
			// DECRYPT THE MESSAGE (String)
			byte[] decryptedMessage = ci.doFinal(encryptedMessage);
		
			
			System.out.println("Xifratge text '" + message + "':"
					+ (new String(encryptedMessage)));
			System.out.println("Desxifratge text '" + (new String(encryptedMessage))
					+ "':" + (new String(decryptedMessage)));
			
			
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
	
	
		
//	RSA is only able to encrypt data to a maximum amount equal to your key size
//	(2048 bits = 256 bytes), minus any padding and header data (11 bytes for PKCS#1 v1.5 padding).
//	MAX encrypted data = 256 - 11 = 245 bytes (MAX key size = 2048 bits)
//	
//	As a result, it is often not possible to encrypt files with RSA directly
//	(and RSA is not designed for this). If you want to encrypt more data, you can do something like:
//	1. Generate a 256-bit random keystring K.
//	2. Encrypt your data with AES-CBC with K.
//	3. Encrypt K with RSA.
//	4. Send both to the other side.
	
	public static void SimpleAsymmetricEncryptionWithWrappedKey()	// RSA
	{
		//String		algorithm = 
		String		AsimAlgorithm = "RSA/ECB/PKCS1Padding";
		String		SimAlgorithm  =  "AES/ECB/PKCS5Padding";
		int			asimkeyLength = 1024;	// 512, 1024, 2048
		int			simkeyLength  = 256;		// 10128, 192, 256
		
		try {
			// INSTANTIATE CIPHERS
			Cipher aci = Cipher.getInstance(AsimAlgorithm);
			Cipher sci = Cipher.getInstance(SimAlgorithm);
			
			// GENERATE KEY PAIR
			KeyPair keys = null;

			KeyPairGenerator asimKeyGen = KeyPairGenerator.getInstance("RSA");
			asimKeyGen.initialize(asimkeyLength);
			keys = asimKeyGen.genKeyPair();

			PrivateKey privateKey = keys.getPrivate();
			PublicKey publicKey = keys.getPublic();
			
			// GENERATE SECRET KEY
			KeyGenerator simKeyGen = KeyGenerator.getInstance("AES");
			simKeyGen.init(simkeyLength);
			SecretKey secretKey = simKeyGen.generateKey();
			
			
			// ENCRYPTING
			// INITIATE CIPHERS
			sci.init(Cipher.ENCRYPT_MODE, secretKey);
			aci.init(Cipher.WRAP_MODE, publicKey);
			
			// ENCRYPT THE SECRET KEY
			byte[] encKey = aci.wrap(secretKey);
			
			// ENCRYPT A MESSAGE (String)
			String message = "Aquest missatge serà xifrat";
			byte[] encryptedMessage = sci.doFinal(message.getBytes());
			
			// DECRYPTING
			// INITIATE ASIMMETRIC CIPHER
			aci.init(Cipher.UNWRAP_MODE, privateKey);
			// DECRYPT THE KEY
			Key decKey = aci.unwrap(encKey, "AES", Cipher.SECRET_KEY);
			
			// INITIATE SIMMETRIC CIPHER
			sci.init(Cipher.DECRYPT_MODE, decKey);
			
			
			// DECRYPT THE MESSAGE (String)
			byte[] decryptedMessage = sci.doFinal(encryptedMessage);
		
			
			System.out.println("Xifratge text '" + message + "':"
					+ (new String(encryptedMessage)));
			System.out.println("Desxifratge text '" + (new String(encryptedMessage))
					+ "':" + (new String(decryptedMessage)));
			
			
		// Exceptions of Cipher.getInstance and KeyGenerator
		} catch (NoSuchAlgorithmException ex) {
		System.err.println("Error: No existeix l'algorisme: " + ex);
		} catch (NoSuchPaddingException ex) {
		System.err.println("Error amb l'algorisme: " + ex);
		// Exceptions of Cipher.init
		} catch (InvalidKeyException ex) {
			System.err.println("Error amb la clau: " + ex);
		// Exceptions of Cipher.doFinal
		} catch (IllegalBlockSizeException ex) {
			System.err.println("Error amb el tamany del bloc de l'algorisme: " + ex);
		} catch (BadPaddingException ex) {
			System.err.println("Error amb el farciment (padding) del bloc de"
					+ " l'algorisme: " + ex);
		}
	}
	
	// Signature examples
	public static void simpleSignature()
	{
		String algorithm = "SHA1withRSA";
		int keyLenght = 512;	// Lenght beetween 512 and 2048, multiply of 64.
		
		byte[] signedData = "Documento a firmar".getBytes(StandardCharsets.UTF_8);
		byte[] signature = null;		// SHA hash ecrypted with a RSA private key
		
		try {
			// GENERATE KEY PAIR
			KeyPair keys = null;

			KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA"); 
			keyGen.initialize(keyLenght);
			keys = keyGen.genKeyPair();

			PrivateKey privateKey = keys.getPrivate();
			PublicKey publicKey = keys.getPublic();
			
			// SIGN DATA WITH SIGNATURE CLASS
			Signature signer = Signature.getInstance(algorithm);
			signer.initSign(privateKey);
			signer.update(signedData);
			signature = signer.sign();
			//~System.out.println(signature.length);	// DELETE
			System.out.println("Signatura de les dades:");
			System.out.println(CryptoUtils.bytesToHex(signature));
		
			try {		// DELETE - Este bloque será la solución a una práctica.
				// DO IT HANDMADE
				// Signature = cipher(alg + hash(data))
				String sha1_alg = "3021300906052B0E03021A05000414";
				Cipher ci = Cipher.getInstance("RSA/ECB/PKCS1Padding");
				ci.init(Cipher.ENCRYPT_MODE, privateKey);
				Digest digest = new Digest("SHA-1");
				
				byte[] planeHash = digest.doHash(signedData);
				byte[] algPlusHash = CryptoUtils.mergeByteArrays(CryptoUtils.hexStringToByteArray(sha1_alg), planeHash);
				byte[] encryptedHash = ci.doFinal(algPlusHash);
				
				// Print signature
				System.out.println("Signatura de les dades (handmade):");
				System.out.println(CryptoUtils.bytesToHex(encryptedHash));
				
				// DO IT HANDMADE
				Cipher ci2 = Cipher.getInstance("RSA/ECB/PKCS1Padding");
				ci2.init(Cipher.DECRYPT_MODE, publicKey);
				byte[] planeHash2 = digest.doHash(signedData);
				byte[] unencryptedHash = ci2.doFinal(encryptedHash);
				
				// Let's see java unencryptedsignature signature:
				byte[] unencryptedsignature = ci2.doFinal(signature);
				System.out.println("Desxifratge de la signatura:");
				System.out.println(CryptoUtils.bytesToHex(unencryptedsignature));
				
				// Print hash and decripted signature
				System.out.println("Hash del document (handmade):");
				System.out.println(CryptoUtils.bytesToHex(unencryptedHash));
				System.out.println("Desxifratge de la signatura (handmade):");
				System.out.println(CryptoUtils.bytesToHex( CryptoUtils.mergeByteArrays(
						CryptoUtils.hexStringToByteArray(sha1_alg), planeHash2)));
				
			} catch (NoSuchPaddingException ex) {
				Logger.getLogger(CryptoExamples.class.getName()).log(Level.SEVERE, null, ex);
			} catch (IllegalBlockSizeException ex) {
				Logger.getLogger(CryptoExamples.class.getName()).log(Level.SEVERE, null, ex);
			} catch (BadPaddingException ex) {
				Logger.getLogger(CryptoExamples.class.getName()).log(Level.SEVERE, null, ex);
			}
			
			// Send 'Signed data' and 'signature' 
			// ---->
			
			// Verify signature
			Signature verifier = Signature.getInstance(algorithm);
			verifier.initVerify(publicKey);
			verifier.update(signedData);
			if (verifier.verify(signature))
				System.out.println("Signatura verificada");
			else
				System.out.println("La signatura no coincideix");
			
		// Eceptions of Signature.getInstance
		} catch (NoSuchAlgorithmException ex) {
			System.err.println("Error: No existeix l'algorisme: "
				+ algorithm + "Exception: " + ex);
		} catch (InvalidKeyException ex) {
			System.err.println("Error amb la clau: " + ex);
		} catch (SignatureException ex) {
			System.err.println("Error amb la signatura: " + ex);
		}
		
	}

	static void storageManagement()
	{
		// Storage JKS without alias passwords
		String ksFile = "MyKeyStore.jks";
		String ksPass = "MyPassword";
		
		try (FileInputStream in = new FileInputStream ("project_files"+File.separator+ksFile)) {
			KeyStore ks = KeyStore.getInstance("JKS");	// Other option: JCEKS
			ks.load(in, ksPass.toCharArray());
			System.out.println("Keys availables: " + ks.size() + '\n');
			
			for(Enumeration<String> alias = ks.aliases(); alias.hasMoreElements();)
			{
				String aliasKey = alias.nextElement();
				System.out.println(aliasKey);
				Certificate cert = ks.getCertificate(aliasKey);
				PublicKey publicKey = cert.getPublicKey();
				PrivateKey privateKey = (PrivateKey)ks.getKey(aliasKey, ksPass.toCharArray());
				System.out.println("Public key:\n" + CryptoUtils.bytesToHex(publicKey.getEncoded()));
				System.out.println("Private key:\n" + CryptoUtils.bytesToHex(privateKey.getEncoded()));
				System.out.println("-------------------\n");
			}
			
			
		} catch (IOException ex) {
			System.err.println("Error amb el fitxer del keyStore: " + ex);
		} catch (KeyStoreException | NoSuchAlgorithmException | UnrecoverableEntryException | CertificateException ex) {
			System.err.println("Error amb el keyStore: " + ex);
		}

	}
	
	
}
