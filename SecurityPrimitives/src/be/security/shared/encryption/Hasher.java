package be.security.shared.encryption;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class Hasher 
{
	private static final String _HASH_ALGORITHM = "SHA-256";
	
	public static byte[] hashObject(byte[] obj)
			throws NoSuchAlgorithmException 
	{
		MessageDigest md = MessageDigest.getInstance(_HASH_ALGORITHM);
		return md.digest(obj);
	}
}
