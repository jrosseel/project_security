package be.security.shared.encryption;

import java.io.IOException;
import java.io.Serializable;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import be.security.shared.settings.GlobalConsts;

public class Hasher 
{
	public static byte[] hashObject(Serializable obj)
			throws NoSuchAlgorithmException, IOException 
	{
		byte[] encodedObj = ByteSerializer.EncodeObject(obj);
		
		return hashBytes(encodedObj);
	}
	
	public static byte[] hashBytes(byte[] obj)
			throws NoSuchAlgorithmException 
	{
		MessageDigest md = MessageDigest.getInstance(GlobalConsts.HASH_ALGORITHM);
		return md.digest(obj);
	}
}
