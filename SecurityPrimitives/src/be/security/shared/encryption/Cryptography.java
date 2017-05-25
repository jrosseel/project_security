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
		
		// Encrypt the object, using the given key
		Cipher rsaenc = Cipher.getInstance("RSA");
		rsaenc.init(Cipher.ENCRYPT_MODE, key);
		
		byte[] encrypted = rsaenc.doFinal(encodedObject);
		
		return encrypted;
	}
	
	/**
	 * Decrypt an in byte-array stored object, and transform it back into the object.
	 */
	public static Object decrypt(byte[] message, Key key) 
			throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IOException, IllegalBlockSizeException, BadPaddingException, ClassNotFoundException 
	{        
		// Depcrypt the object, using the given key
		Cipher rsadec = Cipher.getInstance("RSA");      
        rsadec.init(Cipher.DECRYPT_MODE, key);
        byte[] decrypted = rsadec.doFinal(message);
		
        Object toObject = ByteSerializer.DecodeObject(decrypted);
        
		return toObject;
	}
}
