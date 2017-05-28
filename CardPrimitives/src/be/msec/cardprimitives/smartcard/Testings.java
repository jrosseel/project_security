package be.msec.cardprimitives.smartcard;

import java.io.IOException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.Certificate;
import be.security.shared.keystore.KeyReader;

public class Testings {

	public static void main(String[] args) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException, UnrecoverableKeyException {
		/*
		byte[] b = "65123080040".getBytes();
		printBytes(b);
		String str = new String(b);
		System.out.println(str);*/
		
		KeyReader r = new KeyReader("government", "");
		
		PublicKey pk = r.readPublic("gov_timestamp_server");
		PrivateKey p = r.readPrivate("gov_timestamp_server", "");
		byte[] cert = p.getEncoded();
		printBytes(cert);
		
	}

	private static void printBytes(byte[] data) {
		String sb1 = "";
		for (byte b: data) {
			sb1 +="(byte)0x" +  String.format("%02x", b) + ", ";
		}
		System.out.println(sb1);
		
	}
	
	
}
