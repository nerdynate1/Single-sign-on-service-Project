package com.myteam.project;
import javax.crypto.Cipher;
//import java.security.NoSuchAlgorithmException;
//import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.KeyGenerator;
//import java.security.Key;
//import java.security.InvalidKeyException;
//import javax.crypto.IllegalBlockSizeException;
//import javax.crypto.BadPaddingException;
import javax.crypto.spec.GCMParameterSpec;
import java.security.SecureRandom;
import java.util.Base64;
//import java.security.InvalidAlgorithmParameterException;
import java.nio.charset.StandardCharsets;

public class GCMEncrypt {


	
	public EncryptResult encrypt (String message) throws Exception{ 
		int tagSize = 128;

		// Get a key generator object.
		KeyGenerator aesKeyGen = KeyGenerator.getInstance("AES");

		// Set the key size to 128 bits.
		aesKeyGen.init(128);

		// Generate the key.
		SecretKey aesKey = aesKeyGen.generateKey();

		// Generate the IV.
		SecureRandom rand = new SecureRandom();
		byte[] rawIv = new byte[16];		// Block size of AES.
		rand.nextBytes(rawIv);					// Fill the array with random bytes.
		GCMParameterSpec gcmParams = new GCMParameterSpec(tagSize, rawIv);

		// Set up an AES cipher object.
		Cipher aesCipher = Cipher.getInstance("AES/GCM/NoPadding");

		// Put the cipher in encrypt mode with the specified key.
		aesCipher.init(Cipher.ENCRYPT_MODE, aesKey, gcmParams);

		// Finalize the message. Note: we have specified our type of character
		// encoding for our call to getBytes() this is, on occassion important.
		// Especially if an interface we use mixes UNICODE and ASCII.
		
		byte[] ciphertext = aesCipher.doFinal(message.getBytes(StandardCharsets.UTF_8));

    String encodedCiphertxt = Base64.getEncoder().encodeToString(ciphertext);
    String encodedKey = Base64.getEncoder().encodeToString(aesKey.getEncoded());
	String encodedIV = Base64.getEncoder().encodeToString(rawIv);
		
	return new EncryptResult (encodedCiphertxt, encodedKey, encodedIV);
	}
}