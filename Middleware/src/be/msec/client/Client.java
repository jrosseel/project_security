package be.msec.client;

import be.msec.cardprimitives.smartcard.InstructionCodes;
import be.msec.cardprimitives.smartcard.SignalCodes;
import be.msec.client.connection.IConnection;
import be.msec.client.connection.SimulatedConnection;

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
		
			TimestampVerifier verifier = new TimestampVerifier(c);
							
			if(verifier.isValid())
			{
				System.out.println("Last access time is deprecated. Contacting government to revalidate.");
				verifier.revalidate();	
			}
			
			AuthenticationServiceProvider asp = new AuthenticationServiceProvider(c);
			
			
		} catch (Exception e) {
			throw e;
		}
		finally {
			c.close();  // close the connection with the card
		}
	}
	
	/* private static byte[] filterResponse(byte[] r, int l)
	 * {
		l += 5;
		byte[] s = new byte[r.length - l];
		for(int i = l; i<r.length; i++){
			s[i - l] = r[i];
		}
		return s;
	}*/
	

}
