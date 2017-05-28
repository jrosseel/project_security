package be.gov.main;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import be.security.shared.data.SignedData;
import be.security.shared.keystore.KeyReader;
import be.security.shared.signing.SignatureVerifier;

public class Test {

	public static void main(String[] args) throws UnrecoverableKeyException, InvalidKeyException, KeyStoreException, NoSuchAlgorithmException, CertificateException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, IOException, SignatureException {
		// TODO Auto-generated method stub
		//SignedData<Long> sign = Revalidation.revalidate();
		
		//long time = System.currentTimeMillis()+10;
		//long test = time+10;
		//byte[] time_b = ByteBuffer.allocate(Long.BYTES).putLong(time).array();
		//byte[] time_test = ByteBuffer.allocate(Long.BYTES).putLong(test).array();
	    /*MessageDigest md = MessageDigest.getInstance("SHA-1");
	    byte[] hash = md.digest(time_b);
	    byte[] hash2 = md.digest(time_test);*
	    KeyReader k = new KeyReader("government","");
		PrivateKey gov = k.readPrivate("gov_timestamp_server", "");
		PublicKey gov_pub = k.readPublic("gov_timestamp_server");*/
	    
		SignedData<Long> sign = Revalidation.revalidate();
				
		SignatureVerifier s = new SignatureVerifier("government", "", "gov_timestamp_server"); 
				
		if(s.verify(sign))
		{
			System.out.println("OK");
		}
		else
		{
			System.out.println("Nok");
		}
		
	}
	
	private static void printBytes(byte[] data) {
		String sb1 = "";
		for (byte b: data) {
			sb1 +="0x" +  String.format("%02x", b) + " ";
		}
		System.out.println(sb1);
		
	}

}
