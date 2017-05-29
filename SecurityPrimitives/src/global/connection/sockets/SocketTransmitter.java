package global.connection.sockets;

import java.io.IOException;
import java.io.Serializable;
import java.net.Socket;

import be.security.shared.encryption.ByteSerializer;

/**
 * Class that allows data tranmission over sockets. */
public class SocketTransmitter 
{

	private Socket _socket;
	
	public SocketTransmitter(Socket s) {
		_socket = s;
	}
	
	/**
	 * Sends an object over a client socket. 
	 * 
	 * First sends an integer that tells how many bytes the object is, then sends the actual object.
	 */
	public void Send(Serializable obj) 
			throws IOException 
	{
		byte[] toSend = ByteSerializer.EncodeObject(obj);
		
		_socket.getOutputStream().write(toSend.length);
		_socket.getOutputStream().write(toSend);
	}
	
	/**
	 * Reads an object sent over a client socket.
	 * 
	 * Fills an array based on the object size received.
	 */
	@SuppressWarnings("unchecked")
	public <T extends Serializable> T ReceiveObject()
		throws IOException, Exception
	{
		int objSize = _socket.getInputStream().read();
		if(objSize <= 0)
			throw new Exception("Invalid data sent over the socket.");
			
		byte[] obj = new byte[objSize];
		
		for(int i = 0; i < objSize; i++)
		{
			obj[i] = (byte) _socket.getInputStream().read();
		}
		
		return (T) ByteSerializer.DecodeObject(obj);
	}
}
