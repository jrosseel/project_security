package be.msec.client;

import java.nio.ByteBuffer;

import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

import be.gov.main.Revalidation;
import be.msec.cardprimitives.smartcard.InstructionCodes;
import be.msec.client.connection.IConnection;
import be.security.shared.data.SignedData;

public class TimestampVerifier {

	IConnection _cardConnection;
	
	public TimestampVerifier(IConnection cardConnection) {
		_cardConnection = cardConnection;
	}
	
	public boolean isValid()
			throws Exception 
	{
		// Update time - Step 1: SC <- M
		// Send Hello[CurrentTime] to the card
		System.out.println("Sending \"Hello\" [CurrentTime] to the card");
		
		long current= System.currentTimeMillis();
		// Allocate 13 bytes: 5 for 'Hello' and 8 for the time (long = 8 bytes)
		byte[] hello_current = ByteBuffer.allocate(13).put("Hello".getBytes()).putLong(current).array();

		CommandAPDU command   = new CommandAPDU(InstructionCodes.IDENTITY_CARD_CLA, InstructionCodes.DO_HELLO_INS, 0x00, 0x00, hello_current,0x7f);
		ResponseAPDU response = _cardConnection.transmit(command);		
		
		if (response.getSW()!=0x9000) throw new Exception("Sending current time failed");
		
		System.out.println("Checking if revalidation request is needed");
		short result = response.getData()[hello_current.length+6];	
		
		return result == 0x01;
	}
	
	public void revalidate() 
			throws Exception 
	{
		// Contact government to get current time
		SignedData<Long> sign = Revalidation.revalidate();

		int length_time = 8;
		int length_signature = 64;
		byte[] time_signature = ByteBuffer.allocate(length_time+length_signature).put(sign.signature).putLong(sign.data).array();
		//System.out.println(sig.length);
		
		CommandAPDU  command  = new CommandAPDU(InstructionCodes.IDENTITY_CARD_CLA, InstructionCodes.DO_NEW_TIME_INS, 0x00, 0x00, time_signature,0x7f);
		ResponseAPDU response = _cardConnection.transmit(command);		
		
		printBytes(time_signature);
		
		if (response.getSW()!=0x9000) throw new Exception("Updating current failed");
		printBytes(response.getData());
		//if(result2==0x01)
		//{
			//System.out.println("Time updated succesfully");
		//}
	}
	
	private static void printBytes(byte[] data) {
		String sb1 = "";
		for (byte b: data) {
			sb1 +="0x" +  String.format("%02x", b) + " ";
		}
		System.out.println(sb1);
		
	}
}
