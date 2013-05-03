import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.SocketException;

public class Transmitter {

	// Using UDP instead of TCP so there will be no sequence numbering etc ...
	DatagramSocket socket;
	int maxMessageSize;
	InetAddress otherIP;
	int otherPort;

	//CryptoParameters for symmetric algos: one bytearray (the key)
	//CryptoParameters for asymmetric algos: three bytearrays {ServerPrivateKey,ServerPublicKey,ClientPublicKey}
	public Transmitter(byte[][] CryptoParameters, InetAddress otherIP, int otherPort, int ownPort, int maxMessageSize) throws SocketException {
		this.socket = new DatagramSocket(ownPort);
		this.socket.setSoTimeout(1000);
		this.maxMessageSize = maxMessageSize;
		this.otherIP = otherIP;
		this.otherPort = otherPort;
	}

	// msg can be of ANY length
	public void send(byte[] msg) throws IOException 
	{
		DatagramPacket p;
		for (int i = 0; i < msg.length; i += maxMessageSize) {
			p = new DatagramPacket(msg, i, Math.min(maxMessageSize, msg.length - i), otherIP, otherPort);
			socket.send(p);
		}
	}

	// return of this function can be of arbitrary length
	public byte[] receive() throws TransmissionException, IOException {
		byte dat[] = new byte[maxMessageSize];
		DatagramPacket p = new DatagramPacket(dat, maxMessageSize);
		socket.receive(p);

		byte re[] = new byte[p.getLength()];
		System.arraycopy(p.getData(), 0, re, 0, p.getLength());
		return re;
	}
	
	
}
