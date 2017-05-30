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
	/**
	 * Encrypt an object using a symmetric key
	 */
	public static byte[] encryptAsymmetric(byte[] encodedObject, Key key) 
			throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IOException, IllegalBlockSizeException, BadPaddingException 
	{
		Cipher rsaenc = Cipher.getInstance(GlobalConsts.ASYMM_CRYPTO_ALGORITHM);
		rsaenc.init(Cipher.ENCRYPT_MODE, key);
		
		byte[] encrypted = rsaenc.doFinal(encodedObject);
		
		return encrypted;
	}

	/**
	 * Decrypt a message using an assymetric key
	 */
	public static byte[] decryptAsymmetric(byte[] message, Key key) 
			throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IOException, IllegalBlockSizeException, BadPaddingException 
	{        
		// Depcrypt the object, using the given key
		Cipher rsadec = Cipher.getInstance(GlobalConsts.ASYMM_CRYPTO_ALGORITHM);      
        rsadec.init(Cipher.DECRYPT_MODE, key);
        byte[] decrypted = rsadec.doFinal(message);
		
        return decrypted;
	}
	
	/**
	 * Encrypt an object using a symmetric key
	 */
	public static byte[] encryptSymmetric(byte[] data, Key key) 
			throws IllegalBlockSizeException, BadPaddingException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException
	{
		Cipher aesenc = Cipher.getInstance(GlobalConsts.SYMM_CRYPTO_ALGORITHM);

        aesenc.init(Cipher.ENCRYPT_MODE, key);    
        return aesenc.doFinal(data);
	}
	
	/**
	 * Decrypt an object using a symmetric key
	 */
	public static byte[] decryptSymmetric(byte[] data, Key key) 
			throws IllegalBlockSizeException, BadPaddingException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException
	{
		Cipher aesenc = Cipher.getInstance(GlobalConsts.SYMM_CRYPTO_ALGORITHM);

        aesenc.init(Cipher.DECRYPT_MODE, key);    
        return aesenc.doFinal(data);
	}
}