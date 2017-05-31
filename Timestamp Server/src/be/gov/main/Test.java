package be.gov.main;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.interfaces.RSAPrivateKey;
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
		/*KeyReader k = new KeyReader("card", "123456");
		//RSAPublicKey key = (RSAPublicKey) k.readPublic("card identifier");
		RSAPrivateKey sk = (RSAPrivateKey)k.readPrivate("smartcard", "");
		printBytes(sk.getModulus().toByteArray());
		System.out.println("\n");
		printBytes(sk.getPrivateExponent().toByteArray());
		System.out.println(sk.getModulus().toByteArray().length);
		System.out.println(sk.getPrivateExponent().toByteArray().length);*/
		
		/*KeyReader r = new KeyReader("dokters_unie", "123456");
		RSAPublicKey pub = (RSAPublicKey) r.readPublic("me");
		printBytes(pub.getModulus().toByteArray());
		System.out.println(pub.getModulus().toByteArray().length);
		printBytes(pub.getPublicExponent().toByteArray());
		System.out.println(pub.getPublicExponent().toByteArray().length);
		System.out.println(pub.getEncoded());*/
				
		//byte[] test = ByteBuffer.allocate(257).put("kljdslkjfsdkljfdskl".getBytes()).array();
		//printBytes(test);
		
		/*ByteBuffer test = ByteBuffer.wrap(new byte[]{ (byte)0x0c, (byte)0x40 });
		short numb = test.getShort();
		System.out.println(numb);*/
		
		/*ByteBuffer buffer = ByteBuffer.allocate(Long.BYTES);
	    buffer.put(new byte[]{(byte)0x00, (byte)0x00, (byte)0x01, (byte)0x5c, (byte)0x5e, (byte)0x2b, (byte)0x13, (byte)0x5c});
		buffer.flip();//need flip 
		System.out.println(buffer.getLong());*/
		
		if((byte)0x63<(byte)0x5c)
		{
			System.out.println("kleiner");
		}
		else
		{
			System.out.println("groter");
		}
	}
	
	private static void printBytes(byte[] data) {
		String sb1 = "";
		for (byte b: data) {
			sb1 +="(byte)0x" +  String.format("%02x", b) + ", ";
		}
		System.out.println(sb1);
		
	}
	

}
