package be.msec.client;

import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

import be.msec.cardprimitives.smartcard.InstructionCodes;
import be.msec.cardprimitives.smartcard.SignalCodes;
import be.msec.client.connection.IConnection;
import be.security.shared.data.QueryMedium;
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
		QueryMedium request = _serverConnection.ReceiveObject();
		byte[] query = request.data;
		
		System.out.println("Query received. Fetching attributes.");
		//Send PIN
		CommandAPDU command = new CommandAPDU(InstructionCodes.IDENTITY_CARD_CLA, InstructionCodes.VALIDATE_PIN_INS, 0x00, 0x00,new byte[]{0x01,0x02,0x03,0x04});
		ResponseAPDU response = _cardConnection.transmit(command);

		if (response.getSW()==SignalCodes.SW_VERIFICATION_FAILED) throw new Exception("PIN INVALID");
		else if(response.getSW()!=0x9000) throw new Exception("Exception on the card: " + response.getSW());
		System.out.println("PIN Verified");		
		
		command = new CommandAPDU(InstructionCodes.IDENTITY_CARD_CLA, InstructionCodes.DO_ATTRIBUTE_QUERY, 0x00, 0x00, query);
		response = _cardConnection.transmit(command);

		if(response.getSW()==SignalCodes.SW_AUTHENTICATION_CARD_FAILED) throw new Exception("Authentication failed.");
		if(response.getSW()==SignalCodes.SW_QUERY_RIGHTS_FAILED) throw new Exception("Not the right query rights."); 
		short resp_len = response.getData()[query.length+5];
		byte[] e_attributes = new byte[resp_len];
		for(short i=0; i<response.getData().length; i++)
		{
			e_attributes[i] = response.getData()[query.length+6+i];
		}
		
		System.out.println("Attributes retrieved from card. Sending them to service provider.");
		QueryMedium attrResponse = new QueryMedium();
		attrResponse.data = e_attributes;
		_serverConnection.Send(attrResponse);
	}
}
