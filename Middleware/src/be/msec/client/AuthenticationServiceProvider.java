package be.msec.client;

import java.io.IOException;
import java.net.Socket;
import java.net.UnknownHostException;

import javax.net.SocketFactory;

import be.msec.client.connection.IConnection;
import be.security.shared.settings.GlobalConsts;
import global.connection.sockets.SocketTransmitter;

public class AuthenticationServiceProvider {
	
	IConnection _cardConnection;
	
	public AuthenticationServiceProvider(IConnection cardConnection) {
		_cardConnection = cardConnection;
	}
	
	public void authenticate() 
			throws Exception 
	{
		SocketTransmitter conn = _getConnection();
		
	}
	
	
	
	private SocketTransmitter _getConnection() throws UnknownHostException, IOException 
	{
		SocketFactory ssf = SocketFactory.getDefault();
		
		Socket s = ssf.createSocket(GlobalConsts.GOVERNMENT_SERVER_ADDRESS , GlobalConsts.GOVERNMENT_PORT); // => change to service provider
		return new SocketTransmitter(s);
	}
	
	

}
