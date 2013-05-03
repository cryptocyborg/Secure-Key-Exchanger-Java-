import java.io.BufferedReader;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;


public class Client {
	
	public static void main(String[] args) throws IOException, NoSuchAlgorithmException{


		if (args.length < 2) {
			System.err.println("Usage: Client serverIP serverPort sym/asym");
			return;
		}
		
		boolean useSymmetric = false;
		int serverTCPPort = Integer.valueOf(args[1]);
		InetAddress serverIP = null;
		try{
		serverIP = InetAddress.getByName(args[0]);
		}
		catch(UnknownHostException ex){
			System.err.println("serverIP could not be parsed :(");
			System.exit(0);
		}
		if(args.length >2 && args[2].equals("sym")) useSymmetric = true;
		
		//---------------DH Key generation---------------------------------
		int pBits = 0;
		BigInteger p = null;
		BigInteger q = null;
		BigInteger g = null;
		BigInteger[] clientKeypair = null;
		BigInteger serverPubKey = null;
		//-------------END DH--------------------------------------------
		
		// ----------RSA Keypair generation------------------------------
		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
		keyGen.initialize(1024);
		KeyPair keyPair = keyGen.genKeyPair();
		PrivateKey ClientPrivateKey = keyPair.getPrivate();
		PublicKey ClientPublicKey = keyPair.getPublic();
		// Get the bytes of the public and private keys

		byte[] ClientPrivateKeyBytes = ClientPrivateKey.getEncoded();
		byte[] ClientPublicKeyBytes = ClientPublicKey.getEncoded();
		byte[] ServerPublicKeyBytes = null;

		// how to convert them back:
		// http://www.javafaq.nu/java-example-code-189.html

		// ------------END RSA----------------------------------------------
		
		//--------------UDP ports-------------------------------------------
		int serverPort = -1;
		ServerSocket server = new ServerSocket(0); //find free port:
		int clientPort = server.getLocalPort();
		server.close(); //close it so it will remain free (hopefully ;) )
		//------------END UDP------------------------------------------------


		// -------------------Do handshake ---------------------------------
		Socket socket = new Socket(serverIP,serverTCPPort);
		
		DataOutputStream out = new DataOutputStream(socket.getOutputStream());
		DataInputStream in = new DataInputStream(socket.getInputStream());

		/*
		 * comments on what which command does can be looked up in the server class ;)
		 */
		int command = 0;
		boolean clientinit = false;
		boolean serverinit = false;
		boolean dhSuccess = false;
		
		//first of all: send udp port
		out.write(30);
		out.writeInt(clientPort);
		//then inform server about prefered mode
		if(useSymmetric) out.write(01);
		else {
			out.write(02);
			
			// Send own key
			out.write(10);
			out.writeInt(ClientPublicKeyBytes.length);
			out.write(ClientPublicKeyBytes);
		}
		
		while (!serverinit || !clientinit) {
			command = in.read();
//			System.out.println(command);
			switch (command) {
				
			case 10: //Receive server's key
			{
				int length = in.readInt();
				ServerPublicKeyBytes = new byte[length];
				int offset = 0;
				int numRead = 0;
				while ((offset<length) &&(numRead = in.read(ServerPublicKeyBytes, offset, length - offset)) >= 0) {
					offset += numRead;
				}
			}
				break;
			case 20: //dh p
			{

				int length = in.readInt();
				byte[] tmp = new byte[length];
				int offset = 0;
				int numRead = 0;
				while ((offset<length) &&(numRead = in.read(tmp, offset, length - offset)) >= 0) {
					offset += numRead;
				}
				p = new BigInteger(tmp);
			}
				break;
			case 21: //dh q
			{

				int length = in.readInt();
				byte[] tmp = new byte[length];
				int offset = 0;
				int numRead = 0;
				while ((offset<length) &&(numRead = in.read(tmp, offset, length - offset)) >= 0) {
					offset += numRead;
				}
				q = new BigInteger(tmp);
			}
				break;
			case 22: //dh g
			{

				int length = in.readInt();
				byte[] tmp = new byte[length];
				int offset = 0;
				int numRead = 0;
				while ((offset<length) &&(numRead = in.read(tmp, offset, length - offset)) >= 0) {
					offset += numRead;
				}
				g = new BigInteger(tmp);
			}
				break;
			case 23: //dh public key
			{
				int length = in.readInt();
				byte[] tmp = new byte[length];
				int offset = 0;
				int numRead = 0;
				while ((offset<length) &&(numRead = in.read(tmp, offset, length - offset)) >= 0) {
					offset += numRead;
				}
				serverPubKey = new BigInteger(tmp);
			}
				break;
			case 25:
				pBits = in.readInt();
				break;
			case 30:
				serverPort = in.readInt();
				break;
			case 251: //server is happy ;)
				serverinit = true;
				break;
				
			default:
				System.err.println("Handshake failed!");
				System.exit(-1);
			}
			
			if(p != null && q != null && g != null && clientKeypair == null){
				clientKeypair = DiffieHellman.genKeyPair(p,q, g);
				System.out.println("Generating xc:" + DiffieHellman.byteArrayToHexString(clientKeypair[0].toByteArray()));
				System.out.println("Generating yc:" + DiffieHellman.byteArrayToHexString(clientKeypair[1].toByteArray()));
				
				//send public key
				out.write(24);
				out.writeInt(clientKeypair[1].toByteArray().length);
				out.write(clientKeypair[1].toByteArray());
				System.out.println("Sending yc");
			}
			
			if(pBits != 0 && clientKeypair != null && serverPubKey != null ){
				dhSuccess = true;
			}
			
			//detect if we are happy
			if(!clientinit && serverPort!= -1 && ((ServerPublicKeyBytes != null && useSymmetric == false) || (dhSuccess ==true && useSymmetric == true))){
				out.write(250);
				clientinit = true;
			}

		}
		socket.close();
		// ---------END HANDSHAKE-------------------------------------------
		System.out.println("handshake successful!");
		
		//------------------Second part: using the keys for message sending---------------
		Transmitter trans;
		if(useSymmetric){
			
			//Calculate Shared Secret
			byte [] SharedSecret = DiffieHellman.generateSharedSecret(clientKeypair[0],serverPubKey,p,pBits);
			System.out.println("Calculating shared secret:" + DiffieHellman.byteArrayToHexString(SharedSecret));
			
			//Calculate AES Key
			byte [] AESKey = new byte[128/8];
			byte [] tmp1 = DiffieHellman.genKM(SharedSecret, DiffieHellman.aes128_CBC, 1, 128);
			System.arraycopy(tmp1, 0, AESKey, 0, AESKey.length);
			System.out.println("Calculating AESKey:" + DiffieHellman.byteArrayToHexString(AESKey));	
			
			//Calculate DESMac Key (not parity adjusted)
			byte [] DESMacKey = new byte[64/8];
			tmp1 = DiffieHellman.genKM(SharedSecret, DiffieHellman.desMAC, 1, 64);
			System.arraycopy(tmp1, 0, DESMacKey, 0, DESMacKey.length);
			System.out.println("Calculating DESMacKey:" + DiffieHellman.byteArrayToHexString(DESMacKey));
			
			trans =  new SymIntTransmitter(new byte[][] {AESKey, DESMacKey}, serverIP, serverPort,  clientPort, 1024);
		}
		else {
			
			trans = new PublicKeyTransmitter(new byte[][] {ClientPrivateKeyBytes,ClientPublicKeyBytes,ServerPublicKeyBytes}, serverIP, serverPort,  clientPort, 1024);
		}


		Object lock = new Object();

		String curLine = "";
		BufferedReader bin = new BufferedReader(new InputStreamReader(System.in));

		ReceiverThread rec = new ReceiverThread(lock, trans);
		rec.start();

		while (!(curLine.equals("quit"))) {
			curLine = bin.readLine();
			trans.send(curLine.getBytes());
			synchronized (lock) {
				System.out.println("You: " + curLine);
			}
		}
		rec.kill();
		
		


	}

}
