package data;

import java.io.Serializable;

public class Certificate implements Serializable 
{
	
	public Certificate() {
		
	}

	public String subject;
	public String domain;
	
	public byte[] publicKey;
	
	
	/**
	 *  Serializable 
	 */
	private static final long serialVersionUID = 2471641012911921415L;
	
}
