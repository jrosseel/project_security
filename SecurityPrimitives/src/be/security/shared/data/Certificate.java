package be.security.shared.data;

import java.io.Serializable;
import java.nio.ByteBuffer;

import be.security.shared.encryption.ByteSerializer;

public class Certificate implements Serializable 
{
	
	public Certificate() {
		
	}

	public String subject;
	public int domain;
	
	public byte[] publicKey;
	public long endtime;
	
	
	public byte[] toBytes() {
		byte[] subj = subject.getBytes();
		byte[] end = ByteBuffer.allocate(Long.BYTES).putLong(endtime).array();
		short dom = (short) (domain);
		short sub_len = (short)subj.length;
		short dom_len = Short.BYTES;
		short pub_len = (short)publicKey.length;
		short end_len = (short)end.length;
		short total_length = (short)(sub_len + dom_len + pub_len + end_len + 8);
		//byte[] result = new byte[]; // + 8 => also store all the lengths. Short = 2 bytes
		
		// added the lengths of each parameter. In this way we can more easily get specific parts of the certificate on the card
		byte[] result2 = ByteBuffer.allocate(total_length).putShort(sub_len) 
															.putShort(dom_len)
															.putShort(pub_len)
															.putShort((short)8)
															.put(subject.getBytes())
															.putShort(dom)
															.put(publicKey)
															.putLong(endtime).array();
													
		
		/*for(int i = 0; i < subj.length; i++) 
			result[i] = subj[i];
		
		for(int i = 0; i < dom.length; i++) 
			result[subj.length + i] = dom[i];
		
		for(int i = 0; i < publicKey.length; i++) 
			result[subj.length + dom.length + i] = publicKey[i];*/
		
		return result2;
	}
	
	/**
	 *  Serializable 
	 */
	private static final long serialVersionUID = 2471641012911921415L;
	
}
