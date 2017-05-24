package be.msec.shared.data;

import java.io.Serializable;

public class Certificate implements Serializable {

	public Certificate() {
		
	}


	private String subject;
	private String issuer;
	private String domain;
	
	private byte[] publicKey;
	
	
	
	
	
	/**
	 *  Serializable 
	 */
	private static final long serialVersionUID = 2471641012911921415L;
}
