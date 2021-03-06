package global.connection.sockets;

import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.io.Serializable;
import java.net.Socket;

/**
 * Class that allows data tranmission over sockets. */
public class SocketTransmitter
{

	private Socket _socket;
	private InputStream _in;
	private OutputStream _out;
	
	public SocketTransmitter(Socket s) 
			throws IOException 
	{
		_socket = s;
		_in = _socket.getInputStream();
		_out = _socket.getOutputStream();
	}
	
	/**
	 * Sends an object over a client socket. 
	 * 
	 * First sends an integer that tells how many bytes the object is, then sends the actual object.
	 */
	public void Send(Serializable obj) 
			throws IOException 
	{
		ObjectOutputStream output = new ObjectOutputStream(_out);
		output.writeObject(obj);
	}
	
	/**
	 * Reads an object sent over a client socket.
	 * 
	 * Fills an array based on the object size received.
	 */
	@SuppressWarnings("unchecked")
	public <T extends Serializable> T ReceiveObject()
		throws IOException, ClassNotFoundException
	{

		ObjectInputStream input = new ObjectInputStream(_in);
		return (T) input.readObject();
	}
	
	public void close() 
			throws IOException 
	{
		_socket.close();
	}
}
