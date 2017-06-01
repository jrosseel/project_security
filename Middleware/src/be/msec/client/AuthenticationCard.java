package be.msec.client;

import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

import be.msec.cardprimitives.smartcard.InstructionCodes;
import be.msec.cardprimitives.smartcard.SignalCodes;
import be.msec.client.connection.IConnection;
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
		
		byte[] encrypted_challenge = new byte[16];
		
		CommandAPDU command = new CommandAPDU(InstructionCodes.IDENTITY_CARD_CLA, InstructionCodes.DO_AUTH_CARD, 0x00, 0x00, encrypted_challenge);
		ResponseAPDU response = _cardConnection.transmit(command);

		if(response.getSW()==SignalCodes.SW_AUTHENTICATION_CARD_FAILED) throw new Exception("Authentication failed.");
		System.out.println("Result after card authentication");
		printBytes(response.getData());
		
		
	}
	
	private static void printBytes(byte[] data) {
		String sb1 = "";
		for (byte b: data) {
			sb1 +="(byte)0x" +  String.format("%02x", b) + ", ";
		}
		System.out.println(sb1);
		
	}
	

}
