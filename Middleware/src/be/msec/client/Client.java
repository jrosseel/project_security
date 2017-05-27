package be.msec.client;

import be.msec.cardprimitives.smartcard.InstructionCodes;
import be.msec.cardprimitives.smartcard.SignalCodes;
import be.msec.client.connection.IConnection;
import be.msec.client.connection.SimulatedConnection;

import java.nio.ByteBuffer;

import javax.smartcardio.*;

public class Client {


	/**
	 * @param args
	 */
	public static void main(String[] args) throws Exception {
		IConnection c;

		//Simulation:
		c = new SimulatedConnection();

		//Real Card:
		//c = new Connection();
		//((Connection)c).setTerminal(0); //depending on which cardreader you use
		
		c.connect(); 
		
		try {

			/*
			 * For more info on the use of CommandAPDU and ResponseAPDU:
			 * See http://java.sun.com/javase/6/docs/jre/api/security/smartcardio/spec/index.html
			 */
			
			CommandAPDU a;
			ResponseAPDU r;
			
			//0. create applet (only for simulator!!!)
			a = new CommandAPDU(0x00, 0xa4, 0x04, 0x00,new byte[]{(byte) 0xa0, 0x00, 0x00, 0x00, 0x62, 0x03, 0x01, 0x08, 0x01}, 0x7f);
			r = c.transmit(a);
			System.out.println(r);
			if (r.getSW()!=0x9000) throw new Exception("select installer applet failed");
			
			a = new CommandAPDU(0x80, 0xB8, 0x00, 0x00,new byte[]{0xb, 0x01,0x02,0x03,0x04, 0x05, 0x06, 0x07, 0x08, 0x09,0x00, 0x00, 0x00}, 0x7f);
			r = c.transmit(a);
			System.out.println(r);
			if (r.getSW()!=0x9000) throw new Exception("Applet creation failed");
			
			//1. Select applet  (not required on a real card, applet is selected by default)
			a = new CommandAPDU(0x00, 0xa4, 0x04, 0x00,new byte[]{0x01,0x02,0x03,0x04, 0x05, 0x06, 0x07, 0x08, 0x09,0x00, 0x00}, 0x7f);
			r = c.transmit(a);
			System.out.println(r);
			if (r.getSW()!=0x9000) throw new Exception("Applet selection failed");
			
			//2. Send PIN
			a = new CommandAPDU(InstructionCodes.IDENTITY_CARD_CLA, InstructionCodes.VALIDATE_PIN_INS, 0x00, 0x00,new byte[]{0x01,0x02,0x03,0x04});
			r = c.transmit(a);

			System.out.println(r);
			if (r.getSW()==SignalCodes.SW_VERIFICATION_FAILED) throw new Exception("PIN INVALID");
			else if(r.getSW()!=0x9000) throw new Exception("Exception on the card: " + r.getSW());
			System.out.println("PIN Verified");
		
			// Step 1: SC <- M
			// Send Hello[CurrentTime] to the card
			System.out.println("Sending \"Hello\" [CurrentTime] to the card ...");
			
			long current= System.currentTimeMillis();
			byte[] message = ByteBuffer.allocate(18).put("Hello".getBytes()).putLong(current).array();
			
			a = new CommandAPDU(InstructionCodes.IDENTITY_CARD_CLA, InstructionCodes.DO_HELLO_TIME, 0x00, 0x00, message, 1);
			r = c.transmit(a);		
			
			System.out.println("Checking if revalidation request is needed ...");
			
			// Step 1: SC -> M 
			// Check if revalidation request is needed
			System.out.println(filterResponse(r.getData(), message.length)[0]);
			
			
			
		} catch (Exception e) {
			throw e;
		}
		finally {
			c.close();  // close the connection with the card
		}
	}
	
	private static byte[] filterResponse(byte[] r, int l){
		l += 5;
		byte[] s = new byte[r.length - l];
		for(int i = l; i<r.length; i++){
			s[i - l] = r[i];
		}
		return s;
	}
	
		
	
	

}
