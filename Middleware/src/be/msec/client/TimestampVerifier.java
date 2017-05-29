package be.msec.client;

import java.io.IOException;
import java.net.Socket;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.Signature;

import javax.net.SocketFactory;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

import be.msec.cardprimitives.smartcard.InstructionCodes;
import be.msec.client.connection.IConnection;
import be.security.shared.data.SignedData;
import be.security.shared.encryption.Hasher;
import be.security.shared.keystore.KeyReader;
import be.security.shared.settings.GlobalConsts;
import global.connection.sockets.SocketTransmitter;

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
		if (response.getSW()!=0x9000) throw new Exception("Sending current time failed");
		
		System.out.println("Checking if revalidation request is needed");
		short result = response.getData()[hello_current.length+6];	
		
		return result == 0x01;
	}
	
	public void revalidate() 
			throws Exception 
	{
		/*SocketTransmitter conn = _getConnection();
		
		// Contact government to get current time
		SignedData<Long> timeStamp = conn.ReceiveObject();

		*/

		
		////////////////////// TEST TEST TEST TEST /////////////////////////
		// Hasher.hashObject doesn't produce the right hash, hashBytes does. 
		// Putted everything here to just test if verification works
		KeyReader k = new KeyReader("government", "123456");
		PrivateKey sk = k.readPrivate("gov_timestamp_server", "");
		
		long now = System.currentTimeMillis();
		MessageDigest md = MessageDigest.getInstance(GlobalConsts.HASH_ALGORITHM);
		
		byte[] hash = md.digest(ByteBuffer.allocate(Long.BYTES).putLong(now).array());
		Signature signer;
	    signer = Signature.getInstance("SHA1withRSA");
	    signer.initSign(sk);
	    signer.update(hash);
	    byte[] signature = signer.sign();
		
		int length_time = 8;
		int length_signature = 64;
		byte[] signature_time = ByteBuffer.allocate(length_time+length_signature).put(signature).putLong(now).array();
		
		
		CommandAPDU  command  = new CommandAPDU(InstructionCodes.IDENTITY_CARD_CLA, InstructionCodes.DO_NEW_TIME_INS, 0x00, 0x00, signature_time ,0x7f);
		ResponseAPDU response = _cardConnection.transmit(command);		
				
		if (response.getSW()!=0x9000) throw new Exception("Updating current failed");
		
		////////////////////////////////////

		short result = response.getData()[signature_time.length+6];	
		if(result==0x01)
		{
			System.out.println("Signature verified. Time updated!");
		}
		else
		{
			System.out.println("Signature not verified. Time not updated");
		}
				
	}
	
	private static void printBytes(byte[] data) {
		String sb1 = "";
		for (byte b: data) {
			sb1 +="0x" +  String.format("%02x", b) + " ";
		}
		System.out.println(sb1);
		
	}
	
	private SocketTransmitter _getConnection() throws UnknownHostException, IOException 
	{
		SocketFactory ssf = SocketFactory.getDefault();
		
		Socket s = ssf.createSocket(GlobalConsts.GOVERNMENT_SERVER_ADDRESS , GlobalConsts.GOVERNMENT_PORT);
		return new SocketTransmitter(s);
	}
}
