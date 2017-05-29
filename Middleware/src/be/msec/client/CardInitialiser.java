package be.msec.client;

import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

import be.msec.client.connection.IConnection;

public class CardInitialiser {

	private IConnection _cardConnection;
	private boolean _isSimulated;
	
	public CardInitialiser(IConnection cardConnection, boolean isSimulated) {
		_cardConnection = cardConnection;
		_isSimulated = isSimulated;
	}
	
	public void initialize() 
			throws Exception 
	{
		if(_isSimulated)
		{
			//0. create applet (only for simulator!!!)
			CommandAPDU command = new CommandAPDU(0x00, 0xa4, 0x04, 0x00,new byte[]{(byte) 0xa0, 0x00, 0x00, 0x00, 0x62, 0x03, 0x01, 0x08, 0x01}, 0x7f);
			ResponseAPDU response = _cardConnection.transmit(command);
			System.out.println(response);
			
			if (response.getSW()!=0x9000) 
				throw new Exception("select installer applet failed");
			
			command = new CommandAPDU(0x80, 0xB8, 0x00, 0x00,new byte[]{0xb, 0x01,0x02,0x03,0x04, 0x05, 0x06, 0x07, 0x08, 0x09,0x00, 0x00, 0x00}, 0x7f);
			response = _cardConnection.transmit(command);
			System.out.println(response);
			
			if (response.getSW()!=0x9000) 
				throw new Exception("Applet creation failed");
			
			//1. Select applet  (not required on a real card, applet is selected by default)
			command = new CommandAPDU(0x00, 0xa4, 0x04, 0x00,new byte[]{0x01,0x02,0x03,0x04, 0x05, 0x06, 0x07, 0x08, 0x09,0x00, 0x00}, 0x7f);
			response = _cardConnection.transmit(command);
			System.out.println(response);
			if (response.getSW()!=0x9000) throw new Exception("Applet selection failed");
		}
	}
}
