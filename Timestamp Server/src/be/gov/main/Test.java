package be.gov.main;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.interfaces.RSAPublicKey;

import be.security.shared.keystore.KeyReader;

/*
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
*/
public class Test {

	public static void main(String[] args) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException, UnrecoverableKeyException
	{
		KeyReader k = new KeyReader("government", "123456");
		RSAPublicKey key = (RSAPublicKey) k.readPublic("gov_timestamp_server");
		PrivateKey sk = k.readPrivate("gov_timestamp_server", "");
		printBytes(key.getModulus().toByteArray());
		System.out.println("\n");
		printBytes(key.getPublicExponent().toByteArray());
		System.out.println(key.getModulus().toByteArray().length);
		
		
	}
	
	private static void printBytes(byte[] data) {
		String sb1 = "";
		for (byte b: data) {
			sb1 +="(byte)0x" +  String.format("%02x", b) + ", ";
		}
		System.out.println(sb1);
		
	}
	

}
