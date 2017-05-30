package be.msec.client;

import java.io.IOException;
import java.net.Socket;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.net.SocketFactory;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

import be.msec.cardprimitives.smartcard.InstructionCodes;
import be.msec.cardprimitives.smartcard.SignalCodes;
import be.msec.client.connection.IConnection;
import be.security.shared.data.Certificate;
import be.security.shared.data.SignedData;
import be.security.shared.encryption.Hasher;
import be.security.shared.settings.GlobalConsts;
import be.service.certify.X509CertificateSimplifier;
import global.connection.sockets.SocketTransmitter;
import global.connection.sockets.routing.ServiceProviders;

public class AuthenticationServiceProvider {
	
	IConnection _cardConnection;
	
	public AuthenticationServiceProvider(IConnection cardConnection) {
		_cardConnection = cardConnection;
	}
	
	public void authenticate() 
			throws Exception 
	{
		SocketTransmitter conn = _getConnection();
				
		conn.Send(new Integer(ServiceProviders.BelgianGovernmentIdentity));
		SignedData<Certificate> cert = conn.ReceiveObject();
		byte [] signature = cert.signature;
		printBytes(signature);
		int length_sig = signature.length;
		byte [] cert_sp = cert.data.toBytes();
		printBytes(cert_sp);
		int length_cert = cert_sp.length;
		System.out.println(length_sig + " " + length_cert);
		byte [] signature_cert = ByteBuffer.allocate(256).put(signature).array();		
		CommandAPDU command   = new CommandAPDU(InstructionCodes.IDENTITY_CARD_CLA, InstructionCodes.DO_AUTH_SP, 0x00, 0x00, signature_cert,0x7f);
		ResponseAPDU response = _cardConnection.transmit(command);	
		
		if (response.getSW()!=0x9000) throw new Exception("Verify SPcert failed");
		
		short result = response.getData()[signature_cert.length+6];	
		if(result==0x01)
		{
			System.out.println("Signature verified. Time updated!");
		}
		else
		{
			System.out.println("Signature not verified. Time not updated");
		}
	}
	
	
	
	private SocketTransmitter _getConnection() throws UnknownHostException, IOException 
	{
		SocketFactory ssf = SocketFactory.getDefault();
		
		Socket s = ssf.createSocket(GlobalConsts.SP_SERVER_ADDRESS , GlobalConsts.SP_PORT);
		return new SocketTransmitter(s);
	}
	
	public static void main(String[]args) throws UnrecoverableKeyException, InvalidKeyException, KeyStoreException, NoSuchAlgorithmException, CertificateException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, SignatureException, IOException{
		
		
	}
	
	private static void printBytes(byte[] data) {
		String sb1 = "";
		for (byte b: data) {
			sb1 +="(byte)0x" +  String.format("%02x", b) + ", ";
		}
		System.out.println(sb1);
		
	}

}
