package be.msec.client;

import be.gov.main.Revalidation;
import be.msec.cardprimitives.smartcard.InstructionCodes;
import be.msec.cardprimitives.smartcard.SignalCodes;
import be.msec.client.connection.IConnection;
import be.msec.client.connection.SimulatedConnection;
import be.security.shared.data.SignedData;

import java.nio.ByteBuffer;
import java.text.SimpleDateFormat;
import java.util.Date;

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
															// Dirty instanceof hack, would be better to use debug pragmas
			CardInitialiser initializer = new CardInitialiser(c, c instanceof SimulatedConnection);
			initializer.initialize();
			
			//2. Send PIN
			a = new CommandAPDU(InstructionCodes.IDENTITY_CARD_CLA, InstructionCodes.VALIDATE_PIN_INS, 0x00, 0x00,new byte[]{0x01,0x02,0x03,0x04});
			r = c.transmit(a);

			System.out.println(r);
			if (r.getSW()==SignalCodes.SW_VERIFICATION_FAILED) throw new Exception("PIN INVALID");
			else if(r.getSW()!=0x9000) throw new Exception("Exception on the card: " + r.getSW());
			System.out.println("PIN Verified");
		
			
			
<<<<<<< HEAD
			TimestampVerifier verifier = new TimestampVerifier(c);
			
			System.out.println("Verifying last access time.");
			if(! verifier.isValid())
=======
			/*
			 * r (Response) contains
			 * - Data field = max 255 bytes at a time 
			 * - SW1 = feedback code
			 * - SW2 = feedback code
			 * 
			 * Data (r.getData()) field contains
			 * - All fields of CommandAPDU + length_of_response + response
			 * So:
			 * - CLA = 1 byte
			 * - INS = 1 byte
			 * - P1 = 1 byte
			 * - P2 = 1 byte
			 * - Lc = 1 byte
			 * - data_send_to_card
			 * - length_of_response
			 * - response
			 * 
			 * EXAMPLE:
			 * - bytes send to: 0x48 0x65 0x6c 0x6c 0x6f 0x00 0x00 0x01 0x5c 0x53 0x7a 0xd9 0x66 
			 * - response_card: 0x80 0x28 0x00 0x00 0x0d 0x48 0x65 0x6c 0x6c 0x6f 0x00 0x00 0x01 0x5c 0x53 0x7a 0xd9 0x66  0x01     0x01 
			 * 					CLA	|INS | P1 | P2 |Lc   |                   bytes send to card                         | length | response
			 */
			
			if (r.getSW()!=0x9000) throw new Exception("Sending current time failed");
			
			System.out.println("Checking if revalidation request is needed");

			short result = r.getData()[hello_current.length+6];	
			if(result==0x01)
>>>>>>> origin/master
			{
				System.out.println("Last access time is deprecated. Contacting government to revalidate.");
				verifier.revalidate();
			}
			// Step 1: SC -> M 
			// Check if revalidation request is needed
			//System.out.println(filterResponse(r.getData(), message.length)[0]);
			
			
			
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
