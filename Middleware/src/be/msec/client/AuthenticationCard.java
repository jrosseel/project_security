package be.msec.client;

import java.nio.ByteBuffer;

import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

import be.msec.cardprimitives.smartcard.InstructionCodes;
import be.msec.cardprimitives.smartcard.SignalCodes;
import be.msec.client.connection.IConnection;
import be.security.shared.data.CardAuthenticationMedium;
import global.connection.sockets.SocketTransmitter;

public class AuthenticationCard {
	
	private IConnection _cardConnection;
	private SocketTransmitter _serverConnection;
	
	public AuthenticationCard(IConnection cardConnection, SocketTransmitter serverConnection) {
		_cardConnection = cardConnection;
		_serverConnection = serverConnection;
	}
	
	public void authenticate() throws Exception
	{
		System.out.println("Waiting for Service Provider to send challenge.");
		CardAuthenticationMedium request = _serverConnection.ReceiveObject();
		
		byte[] encrypted_challenge = request.data;
		CommandAPDU command = new CommandAPDU(InstructionCodes.IDENTITY_CARD_CLA, InstructionCodes.DO_AUTH_CARD, 0x00, 0x00, encrypted_challenge);
		ResponseAPDU response = _cardConnection.transmit(command);

		if(response.getSW()==SignalCodes.SW_AUTHENTICATION_CARD_FAILED) throw new Exception("Authentication failed.");
		System.out.println("Received encrypted challenge: ");
		printBytes(encrypted_challenge);
		System.out.println("Result after card authentication");
		System.out.println("The msg is: ");
		short len_encrypted = ByteBuffer.wrap(new byte[]{0x00, response.getData()[encrypted_challenge.length+5]}).getShort();
		
		byte[]to_send = new byte[len_encrypted];
		for(short i=0; i<len_encrypted;i++)
		{
			to_send[i] = response.getData()[encrypted_challenge.length+6+i];
		}
		
		printBytes(to_send);
		CardAuthenticationMedium m = new CardAuthenticationMedium();
		m.data = to_send;
		_serverConnection.Send(m);
		
		System.out.println("Encrypted array sent to server");
		ReleaseAttributes ra = new ReleaseAttributes(_cardConnection, _serverConnection);
		ra.release();
	}
	
	private static void printBytes(byte[] data) {
		String sb1 = "";
		for (byte b: data) {
			sb1 +="(byte)0x" +  String.format("%02x", b) + ", ";
		}
		System.out.println(sb1);
		
	}
	

}
