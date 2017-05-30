package be.security.shared.data;

import java.io.Serializable;

import be.security.shared.encryption.ByteSerializer;

public class Certificate implements Serializable 
{
	
	public Certificate() {
		
	}

	public String subject;
	public int domain;
	
	public byte[] publicKey;
	
	
	public byte[] toBytes() {
		byte[] subj = subject.getBytes();
		byte[] dom = ByteSerializer.EncodeInt(domain);
		
		byte[] result = new byte[subj.length + dom.length + publicKey.length];
		for(int i = 0; i < subj.length; i++) 
			result[i] = subj[i];
		
		for(int i = 0; i < dom.length; i++) 
			result[subj.length + i] = dom[i];
		
		for(int i = 0; i < publicKey.length; i++) 
			result[subj.length + dom.length + i] = publicKey[i];
		
		return result;
	}
	
	/**
	 *  Serializable 
	 */
	private static final long serialVersionUID = 2471641012911921415L;
	
}
