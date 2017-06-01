package be.msec.client;

import java.nio.ByteBuffer;

import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

import be.msec.cardprimitives.smartcard.InstructionCodes;
import be.msec.cardprimitives.smartcard.SignalCodes;
import be.msec.client.connection.IConnection;
import be.security.shared.data.CardAuthenticationMedium;
import global.connection.sockets.SocketTransmitter;

public class ReleaseAttributes {
	
	private IConnection _cardConnection;
	private SocketTransmitter _serverConnection;
	
	public ReleaseAttributes(IConnection cardConnection, SocketTransmitter serverConnection) {
		_cardConnection = cardConnection;
		_serverConnection = serverConnection;
	}
	
	public void release() throws Exception
	{
		System.out.println("Waiting for Service Provider to send query.");
		//CardAuthenticationMedium request = _serverConnection.ReceiveObject();
		
		//Send PIN
		CommandAPDU command = new CommandAPDU(InstructionCodes.IDENTITY_CARD_CLA, InstructionCodes.VALIDATE_PIN_INS, 0x00, 0x00,new byte[]{0x01,0x02,0x03,0x04});
		ResponseAPDU response = _cardConnection.transmit(command);

		if (response.getSW()==SignalCodes.SW_VERIFICATION_FAILED) throw new Exception("PIN INVALID");
		else if(response.getSW()!=0x9000) throw new Exception("Exception on the card: " + response.getSW());
		System.out.println("PIN Verified");		
		
		byte[] query = new byte[20];
		command = new CommandAPDU(InstructionCodes.IDENTITY_CARD_CLA, InstructionCodes.DO_ATTRIBUTE_QUERY, 0x00, 0x00, query);
		response = _cardConnection.transmit(command);

		if(response.getSW()==SignalCodes.SW_AUTHENTICATION_CARD_FAILED) throw new Exception("Authentication failed");
		 
		short resp_len = response.getData()[query.length+5];
		byte[] e_attributes = new byte[resp_len];
		for(short i=0; i<response.getData().length; i++)
		{
			e_attributes[i] = response.getData()[query.length+6+i];
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
