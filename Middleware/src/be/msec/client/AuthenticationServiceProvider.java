package be.msec.client;

import java.io.IOException;
import java.io.Serializable;
import java.net.Socket;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;

import javax.net.SocketFactory;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

import be.msec.cardprimitives.smartcard.InstructionCodes;
import be.msec.cardprimitives.smartcard.SignalCodes;
import be.msec.client.connection.IConnection;
import be.security.shared.data.Certificate;
import be.security.shared.data.KeyNegotiation;
import be.security.shared.data.KeyNegotiationResponse;
import be.security.shared.data.SignedData;
import be.security.shared.settings.GlobalConsts;
import global.connection.sockets.SocketTransmitter;
import global.connection.sockets.routing.ServiceProviders;

public class AuthenticationServiceProvider
{	
	private IConnection _cardConnection;
	private SocketTransmitter _serverConnection;
	
	public AuthenticationServiceProvider(IConnection cardConnection) {
		_cardConnection = cardConnection;
	}
	
	public void authenticate() 
			throws Exception 
	{
		_serverConnection = _createConnection();
				
		_serverConnection.Send(new Integer(ServiceProviders.DoktersUnie));
		SignedData<Certificate> cert = _serverConnection.ReceiveObject();
		byte [] signature = cert.signature;
		printBytes(signature);
		short length_sig = (short)signature.length;
		byte [] cert_sp = cert.data.toBytes();
		printBytes(cert_sp);
		short length_cert = (short)cert_sp.length;
		System.out.println(length_sig + " " + length_cert);
		byte[] signature_cert = ByteBuffer.allocate(length_sig+length_cert+4).putShort(length_sig).putShort(length_cert).put(signature).put(cert_sp).array();
		if(signature_cert.length > MAX_LEN) 
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
		if (response.getSW()==SignalCodes.SW_VERIFICATION_CERT_FAILED) throw new Exception("Verification of certificate failed");
		if (response.getSW()==SignalCodes.SW_TIME_CERTIFICATE_EXPIRED) throw new Exception("Time on certificate expired");
		if(response.getData()[7]==0x01)
		{
			System.out.println("Authentication service provider: OK!");
			
			// get encrypted messages Ekey and Emsg
			command = new CommandAPDU(InstructionCodes.IDENTITY_CARD_CLA, InstructionCodes.GET_AUTH_SER_EKEY, 0x00, 0x00, new byte[1]);
			response = _cardConnection.transmit(command);
			System.out.println("The Ekey is: ");
			
			int length_ekey = response.getData()[6]; // => automatically converts byte to int
			byte[] ekey = new byte[length_ekey];
			for(int i=0; i<length_ekey; i++)
			{
				ekey[i] = response.getData()[i+7];
			}
			printBytes(ekey);
						
			command = new CommandAPDU(InstructionCodes.IDENTITY_CARD_CLA, InstructionCodes.GET_AUTH_SER_EMSG, 0x00, 0x00, new byte[1]);
			response = _cardConnection.transmit(command);
			System.out.println("The Emsg is: ");
			int length_emsg = response.getData()[6] & 0xFF; // => automatically converts byte to int. & 0xFF so it's always positive
			System.out.println(length_emsg);
			byte[] emsg = new byte[length_emsg];
			for(int i=0; i<length_emsg; i++)
			{
				emsg[i] = response.getData()[i+7];
			}
			printBytes(emsg);
			
			KeyNegotiation keyNeg = new KeyNegotiation();
			keyNeg.encryptedSymmetricKey = ekey;
			keyNeg.encryptedKeyNegotiationChallenge = emsg;
			// connect to server and send emsg and ekey
			System.out.println("Sending key negotiation answer.");
			_serverConnection.Send(keyNeg);
			
			// receive key response
			KeyNegotiationResponse keyResponse = _serverConnection.ReceiveObject();
			System.out.println("Received challenge response");
			
			byte[] key_resp = keyResponse.challengeResponse;
			printBytes(key_resp);
			
			command = new CommandAPDU(InstructionCodes.IDENTITY_CARD_CLA, InstructionCodes.DO_CHECK_SERVER_RESP, 0x00, 0x00, key_resp);
			response = _cardConnection.transmit(command);
			if (response.getSW()==SignalCodes.SW_CHALLENGE_FAILED)
				throw new Exception("Challenge failed.");
			System.out.println("Service provider authenticated!");
			
		}
	}

	private SocketTransmitter _createConnection() throws UnknownHostException, IOException 
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
