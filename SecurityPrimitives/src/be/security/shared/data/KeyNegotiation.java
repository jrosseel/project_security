package be.security.shared.data;

public class KeyNegotiation 
{
	// Symmetric key, encrypted using the PK of SP.
	public byte[] encryptedSymmetricKey;
	
	// Challenge, encrypted using the symmetric key 
	public byte[] encryptedKeyNegotiationChallenge;

}