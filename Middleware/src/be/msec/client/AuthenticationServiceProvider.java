package be.msec.client;

import java.io.IOException;
import java.net.Socket;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;

import javax.net.SocketFactory;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

import be.msec.cardprimitives.smartcard.InstructionCodes;
import be.msec.client.connection.IConnection;
import be.security.shared.data.Certificate;
import be.security.shared.data.SignedData;
import be.security.shared.settings.GlobalConsts;
import global.connection.sockets.SocketTransmitter;
import global.connection.sockets.routing.ServiceProviders;

public class AuthenticationServiceProvider
{	
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
		byte[] signature_cert = ByteBuffer.allocate(length_sig+length_cert).put(signature).put(cert_sp).array();
		if(signature.length > MAX_LEN) 
			_sendInPieces(signature_cert);
		
		
	}
	
	private static final int MAX_LEN = 255;
	
	private void _sendInPieces(byte[] signature_cert) throws Exception 
	{
		byte[] buffer = new byte[MAX_LEN];
		for(int i =0; i< Math.ceil((double) signature_cert.length / MAX_LEN); i++)
		{
			System.arraycopy(signature_cert, MAX_LEN*i, buffer, 0, Math.min(MAX_LEN,  signature_cert.length - (MAX_LEN * i)));
			
			CommandAPDU command = new CommandAPDU(InstructionCodes.IDENTITY_CARD_CLA, InstructionCodes.DO_AUTH_SP_STEP, 0x00, 0x00, buffer);
			ResponseAPDU response = _cardConnection.transmit(command);
			
			if (response.getSW()!=0x9000)
				throw new Exception("Failed to send piece of signature.");
		}
		CommandAPDU command = new CommandAPDU(InstructionCodes.IDENTITY_CARD_CLA, InstructionCodes.DO_AUTH_SP, 0x00, 0x00, new byte[1]);
		ResponseAPDU response = _cardConnection.transmit(command);
		

		if (response.getSW()!=0x9000) throw new Exception("Verify SPcert failed");
		
		short result = response.getData()[signature_cert.length+6];	
		if(result==0x01)
		{
			System.out.println("Signature verified. Time updated!");
		}
		else
			System.out.println("Signature not verified. Time not updated");
	
	}

	private SocketTransmitter _getConnection() throws UnknownHostException, IOException 
	{
		SocketFactory ssf = SocketFactory.getDefault();
		
		Socket s = ssf.createSocket(GlobalConsts.SP_SERVER_ADDRESS , GlobalConsts.SP_PORT);
		return new SocketTransmitter(s);
	}
	
	
	private static void printBytes(byte[] data) {
		String sb1 = "";
		for (byte b: data) {
			sb1 +="(byte)0x" +  String.format("%02x", b) + ", ";
		}
		System.out.println(sb1);
		
	}

}
