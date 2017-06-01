package be.security.shared.data;

import java.nio.ByteBuffer;
import java.util.Arrays;

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
		// we can't just go from 8 to end of bytearray to get subject => some 0's are added because length of array%16 should be 0
		short subj_len = ByteBuffer.wrap(new byte[]{data[2], data[3]}).getShort();
		result.challenge = ByteBuffer.wrap(new byte[]{data[4], data[5], data[6], data[7]}).getInt();
		printBytes(Arrays.copyOfRange(data, 8, subj_len+8));
		result.subject = new String(Arrays.copyOfRange(data, 8, subj_len+8));
		return result;
	}
	
	private static void printBytes(byte[] data) {
		String sb1 = "";
		for (byte b: data) {
			sb1 +="(byte)0x" +  String.format("%02x", b) + ", ";
		}
		System.out.println(sb1);
		
	}
	
}