import java.io.BufferedReader;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;

public class Server {

	//Usually there is only one TCP-connection that is used to exchange / agree on keys first and later on to
	//send messages. This won't be used here since the "send message" part is required to be implemented manually.
	//Therefore we choose to use UDP - in order to simulate distinct message passing. 
	//
	//As a result the program is split in two halves: First half is to exchange / agree on keys. This half uses
	//TCP since it provides reliable transfer. 
	//
	//The second half uses UDP and hereby simulates sending of distinct messages instead of sending streams.
	
	
	
	/**
	 * @param args
	 */
	public static void main(String[] args) throws IOException, NoSuchAlgorithmException {

				
		if (args.length < 1) {
			System.err.println("Usage: Server listeningPort");
			return;
		}

		int listeningPort = Integer.valueOf(args[0]);

		// ----------RSA Keypair generation------------------------------
		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
		keyGen.initialize(1024);
		KeyPair keyPair = keyGen.genKeyPair();
		PrivateKey ServerPrivateKey = keyPair.getPrivate();
		PublicKey ServerPublicKey = keyPair.getPublic();
		// Get the bytes of the public and private keys

		byte[] ServerPrivateKeyBytes = ServerPrivateKey.getEncoded();
		byte[] ServerPublicKeyBytes = ServerPublicKey.getEncoded();
		byte[] ClientPublicKeyBytes = null;

		// how to convert them back:
		// http://www.javafaq.nu/java-example-code-189.html

		// ------------END RSA----------------------------------------------
		
		//---------------DH Key generation---------------------------------
		int pBits = 768;
		int qBits = 256;
		BigInteger[] pq = DiffieHellman.genPQ(pBits,qBits,100);
		System.out.println("Generating p:" + DiffieHellman.byteArrayToHexString(pq[0].toByteArray()));
		System.out.println("Generating q:" + DiffieHellman.byteArrayToHexString(pq[1].toByteArray()));
		BigInteger g = DiffieHellman.genG(pq[0],pq[1]);
		System.out.println("Generating g:" + DiffieHellman.byteArrayToHexString(g.toByteArray()));
		BigInteger[] serverKeypair = DiffieHellman.genKeyPair(pq[0],pq[1], g);
		System.out.println("Generating xs:" + DiffieHellman.byteArrayToHexString(serverKeypair[0].toByteArray()));
		System.out.println("Generating ys:" + DiffieHellman.byteArrayToHexString(serverKeypair[1].toByteArray()));
		BigInteger clientPubKey = null;
		//-------------END DH--------------------------------------------
		
		//--------------UDP ports-------------------------------------------
		int clientPort = -1;
		ServerSocket server = new ServerSocket(0); //find free port:
		int serverPort = server.getLocalPort();
		server.close(); //close it so it will remain free (hopefully ;) )
		//------------END UDP------------------------------------------------


		// -------------------Do handshake ---------------------------------
		ServerSocket ssocket = new ServerSocket(listeningPort);
		Socket socket = ssocket.accept();
		InetAddress clientIP = socket.getInetAddress();
		
		DataOutputStream out = new DataOutputStream(socket.getOutputStream());
		DataInputStream in = new DataInputStream(socket.getInputStream());

		/*
		 * Keep it simple: command Syntax: [command, payloadlength, payload] (byte, integer, variable) 
		 * if there is no payload then just the command and if there is a pyload of fixed length then [command, payload]
		 * 01: client->server: client will use symmetric integrity without confidentiality 
		 * 02: client->server: client will use asymmetric integrity without confidentiality
		 * 10: client<->server: public RSA key
		 * 20: server->client: Diffie-Hellman p
		 * 21: server->client: Diffie-Hellman q
		 * 22: server->client: Diffie-Hellman g
		 * 23: server->client: Diffie-Hellman public key
		 * 24: client->server: Diffie-Hellman public key 
		 * 25: server->client: Diffie-Hellman pBits
		 * 30: client<->server: UDP communicationport;
		 * 250: client->server: handshake completed succesfully 
		 * 251: server->client: handshake complete succesfully
		 */
		int command = 0;
		boolean clientinit = false;
		boolean serverinit = false;
		boolean dhSuccess = false;
		boolean useSymmetric = false;
		
		//first of all: send udp port
		out.write(30);
		out.writeInt(serverPort);
		
		while (!serverinit || !clientinit) {
			command = in.read();
//			System.out.println(command);
			switch (command) {
			case 01:
				useSymmetric = true;
				
				//Send DH public parameters
				//p
				out.write(20);
				out.writeInt(pq[0].toByteArray().length);
				out.write(pq[0].toByteArray());
				System.out.println("Sending p");
				
				//q
				out.write(21);
				out.writeInt(pq[1].toByteArray().length);
				out.write(pq[1].toByteArray());
				System.out.println("Sending q");
				
				//g
				out.write(22);
				out.writeInt(g.toByteArray().length);
				out.write(g.toByteArray());
				System.out.println("Sending g");
				
				//public key
				out.write(23);
				out.writeInt(serverKeypair[1].toByteArray().length);
				out.write(serverKeypair[1].toByteArray());
				System.out.println("Sending ys");
				
				//public key
				out.write(25);
				out.writeInt(pBits);
				break;
				
			case 02:
				useSymmetric = false;
				
				// Send own key
				out.write(10);
				out.writeInt(ServerPublicKeyBytes.length);
				out.write(ServerPublicKeyBytes);
				break;
				
			case 10: //Receive client's key
			{
				int length = in.readInt();
				ClientPublicKeyBytes = new byte[length];
				int offset = 0;
				int numRead = 0;
				while ((offset<length) &&(numRead = in.read(ClientPublicKeyBytes, offset, length - offset)) >= 0) {
					offset += numRead;
				}
			}
				break;
			case 24: //dh public key
			{
				dhSuccess = true;
				int length = in.readInt();
				byte[] tmp = new byte[length];
				int offset = 0;
				int numRead = 0;
				while ((offset<length) &&(numRead = in.read(tmp, offset, length - offset)) >= 0) {
					offset += numRead;
				}
				clientPubKey = new BigInteger(tmp);
			}
				break;
			case 30:
				clientPort = in.readInt();
				break;
			case 250: //client is happy ;)
				clientinit = true;
				break;
				
			default:
				System.err.println("Handshake failed!");
				System.exit(-1);
			}
			
			//detect if we are happy
			if(!serverinit && clientPort!= -1 && ((ClientPublicKeyBytes != null && useSymmetric == false) || (dhSuccess ==true && useSymmetric == true))){
				out.write(251);
				serverinit = true;
			}

		}
		socket.close();
		ssocket.close();
		// ---------END HANDSHAKE-------------------------------------------
		System.out.println("handshake successful!");
		
		//------------------Second part: using the keys for message sending---------------
		Transmitter trans;
		if(useSymmetric){
			
			//Calculate Shared Secret
			byte [] SharedSecret = DiffieHellman.generateSharedSecret(serverKeypair[0],clientPubKey,pq[0],pBits);
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
			
			trans =  new SymIntTransmitter(new byte[][] {AESKey, DESMacKey}, clientIP, clientPort, serverPort, 1024);
		}
		else {
			trans =  new PublicKeyTransmitter(new byte[][] {ServerPrivateKeyBytes,ServerPublicKeyBytes,ClientPublicKeyBytes}, clientIP, clientPort, serverPort, 1024);
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
