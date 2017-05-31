package be.security.shared.data;

import java.io.Serializable;

public class KeyNegotiation implements Serializable
{
	// Symmetric key, encrypted using the PK of SP.
	public byte[] encryptedSymmetricKey;
	
	// Challenge, encrypted using the symmetric key 
	public byte[] encryptedKeyNegotiationChallenge;

	/**
	 * 
	 */
	private static final long serialVersionUID = -1118136793436991081L;
}