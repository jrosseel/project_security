package be.security.shared.encryption;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import be.security.shared.settings.GlobalConsts;


/**
 * Class used to encrypt and decrypt data.
 */
public class Cryptography 
{	
	public static byte[] encryptAsync(byte[] encodedObject, Key key) 
			throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IOException, IllegalBlockSizeException, BadPaddingException 
	{
		// Encrypt the object, using the given key
		Cipher rsaenc = Cipher.getInstance(GlobalConsts.CRYPTO_ALGORITHM);
		rsaenc.init(Cipher.ENCRYPT_MODE, key);
		
		byte[] encrypted = rsaenc.doFinal(encodedObject);
		
		return encrypted;
	}

	/**
	 * Decrypt a message
	 */
	public static byte[] decryptAsync(byte[] message, Key key) 
			throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IOException, IllegalBlockSizeException, BadPaddingException 
	{        
		// Depcrypt the object, using the given key
		Cipher rsadec = Cipher.getInstance(GlobalConsts.CRYPTO_ALGORITHM);      
        rsadec.init(Cipher.DECRYPT_MODE, key);
        byte[] decrypted = rsadec.doFinal(message);
		
        return decrypted;
	}
}
