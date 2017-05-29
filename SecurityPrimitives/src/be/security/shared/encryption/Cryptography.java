package be.security.shared.encryption;

import java.io.IOException;
import java.io.Serializable;
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
	 * Encrypt an object, and transform it into a bytearray.
	 * 
	 * @param obj: Serializable object. This is mandatory to ensure we can easily transform the bytes back into an object after decryption.
	 */
	public static byte[] encrypt(Serializable obj, Key key) 
		throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IOException, IllegalBlockSizeException, BadPaddingException 
	{
		// Encode the object
		byte[] encodedObject = ByteSerializer.EncodeObject(obj);

		return encrypt(encodedObject, key);
	}
	
	public static byte[] encrypt(byte[] encodedObject, Key key) 
			throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IOException, IllegalBlockSizeException, BadPaddingException 
	{
		// Encrypt the object, using the given key
		Cipher rsaenc = Cipher.getInstance(GlobalConsts.CRYPTO_ALGORITHM);
		rsaenc.init(Cipher.ENCRYPT_MODE, key);
		
		byte[] encrypted = rsaenc.doFinal(encodedObject);
		
		return encrypted;
	}

	/**
	 * Decrypt an in byte-array stored object, and transform it back into the object.
	 */
	@SuppressWarnings("unchecked")
	public static <T extends Serializable> T decrypt(byte[] message, Key key) 
			throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IOException, IllegalBlockSizeException, BadPaddingException, ClassNotFoundException 
	{        
		// Depcrypt the object, using the given key
		Cipher rsadec = Cipher.getInstance(GlobalConsts.CRYPTO_ALGORITHM);      
        rsadec.init(Cipher.DECRYPT_MODE, key);
        byte[] decrypted = rsadec.doFinal(message);
		
        Object toObject = ByteSerializer.DecodeObject(decrypted);
        
		return (T) toObject;
	}
}
