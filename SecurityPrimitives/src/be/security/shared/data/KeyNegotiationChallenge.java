package be.security.shared.data;

import java.nio.ByteBuffer;

import be.security.shared.encryption.ByteSerializer;

/**
 * Inner class that is used for storing the symmetric key
 */
public class KeyNegotiationChallenge {
	public int challenge;
	
	public String subject;
	
	public byte[] getBytes() {
		byte[] chall = ByteSerializer.EncodeInt(challenge);
		byte[] spSubj = subject.getBytes();
		
							// chall is 4 bytes, so for decoding purposes it comes first.
		return ByteSerializer.concatArrays(chall, spSubj);
	}
	
	public static KeyNegotiationChallenge decode(byte[] data) 
	{
		KeyNegotiationChallenge result = new KeyNegotiationChallenge();
		result.challenge = ByteBuffer.wrap(data).getInt();
		result.subject = new String(data);
		
		return result;
	}
	
}