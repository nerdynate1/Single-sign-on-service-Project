import javax.crypto.Cipher;
import java.security.NoSuchAlgorithmException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.BadPaddingException;
import java.util.Base64;
import java.util.Scanner;
import java.security.InvalidAlgorithmParameterException;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.AEADBadTagException;

public class GCMDecrypt {

	public String decrypt (String base64CipherTxt, String base64Key, String base64Iv) throws Exception { 
	
		int tagSize = 128;		// 128-bit authentication tag.

		byte[] cipherTxtBytes = Base64.getDecoder().decode(base64CipherTxt);
    	byte[] keyBytes = Base64.getDecoder().decode(base64Key);
		byte[] ivBytes = Base64.getDecoder().decode(base64Iv);
		

		// Set up an AES cipher object.
		Cipher aesCipher = Cipher.getInstance("AES/GCM/NoPadding");


		// Setup the key.
		SecretKeySpec aesKey = new SecretKeySpec(keyBytes, "AES");

		// Put the cipher in encrypt mode with the specified key.
		aesCipher.init(Cipher.DECRYPT_MODE, aesKey,
		    new GCMParameterSpec(tagSize, ivBytes));

		// Finalize the message.
		byte[] plaintextBytes = aesCipher.doFinal(cipherTxtBytes);

    return new String(plaintextBytes, "US-ASCII");

	}
}