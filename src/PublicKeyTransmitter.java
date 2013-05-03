import javax.crypto.*;
import java.net.InetAddress;
import java.net.SocketException;
import java.security.*;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;


/**
 * This class implements a simple sending and receiving control mechanism based on public key encryption.
 * The packet constructed is with the following structure:
 * 	1. Type of digest used  1 = SHA-256 2= SHA-1 3=MD5 - at the moment not implemented
 *	2. Length of the text message
 * 	3. Length of the encrypted part
 * 	4. Message
 *	5. Encrypted part - encrypted with RSA private key of the sender
 *  5.1	Counter - packet counter against replay attacks
 *  5.2	Digest length 
 *  5.3	Digest - digest based on the type of digest chosen
 *  
 * @author Margus Välja
 */
public class PublicKeyTransmitter extends Transmitter {
	int lastCounter=0;
	int counter = 1;
	int maxSize=0; 
	byte[][] cryptoParameters = null;
	KeyFactory keyFactory;
	/**
	 * @param CryptoParameters
	 * @param otherIP
	 * @param otherPort
	 * @param ownPort
	 * @param maxMessageSize
	 * @throws SocketException
	 * @throws NoSuchAlgorithmException 
	 */
	PublicKeyTransmitter(byte[][] CryptoParameters, InetAddress otherIP, int otherPort, int ownPort, int maxMessageSize) throws SocketException, NoSuchAlgorithmException{
		super(CryptoParameters, otherIP, otherPort, ownPort, maxMessageSize);
		this.cryptoParameters = CryptoParameters;
		keyFactory = KeyFactory.getInstance("RSA");
		maxSize = maxMessageSize - 140; //minus protocol payload size
	}
	
	/**
	 * 
	 * Constructs the packet
	 * @param semsg Message text
	 * @return Packet as a byte array
	 */
	public byte[] construct(byte[] semsg)  {
		byte[] digest, encrypted = null;
		ByteArrayOutputStream byteStream1 = new ByteArrayOutputStream();
		DataOutputStream dataStream1 = new DataOutputStream(byteStream1);
		ByteArrayOutputStream byteStream2 = new ByteArrayOutputStream();
		DataOutputStream dataStream2 = new DataOutputStream(byteStream2);
		byte type = 1; 
		try{
			MessageDigest md = MessageDigest.getInstance("SHA-256");
			digest = md.digest(semsg);
			dataStream1.writeInt(counter++);
			dataStream1.writeInt(digest.length);
			dataStream1.write(digest);
			dataStream1.flush();
			encrypted = this.rsaModify(byteStream1.toByteArray(),cryptoParameters[0], 1);
			dataStream2.write(type); //Type of digest
			dataStream2.writeInt(semsg.length); 	//Length of the message
			dataStream2.writeInt(encrypted.length); //Length of the encrypted part
			dataStream2.write(semsg);				//The message
			dataStream2.write(encrypted);			//The digest encrypted with the server PrivateKey
			dataStream2.flush();
		
		}catch(Exception e){
			System.err.println("Caught an Exception while constructing message");
			System.err.println("getMessage():" + e.getMessage());
			System.err.println("getLocalizedMessage():" +e.getLocalizedMessage());
			System.err.println("toString():" + e);
			System.err.println("printStackTrace():");
			e.printStackTrace();
			throw new RuntimeException(e);
	}
		return byteStream2.toByteArray();		
	}	
			
	/**
	 * Encrypts and decrypts input
	 * @param data Data to be encrypted/decrypted
	 * @param key The key that will be used for encryption/decryption
	 * @param mode Decrypt 2, encrypt mode 1
	 * @return Encrypted/decrypted data is returned
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 * @throws InvalidKeySpecException
	 * @throws InvalidKeyException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 */
	public byte[] rsaModify(byte[] data, byte[] key, int mode) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeySpecException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException  {
		if (mode!=1&&mode!=2){return null;}
		Cipher cipher = Cipher.getInstance("RSA");
		if(mode==1){
        	EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(key);
        	PrivateKey privateKey2 = keyFactory.generatePrivate(privateKeySpec);
        	cipher.init(mode, privateKey2);
		}
		if(mode==2){
			EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(key);
        	PublicKey publicKey2 = keyFactory.generatePublic(publicKeySpec);
    		cipher.init(mode, publicKey2);
		}
		byte[] cipherData = cipher.doFinal(data);
		return cipherData;
	}
	
	/**
	 * Deconstructs the packet - strips everything unnecessary and checks the message for integrity.
	 * @param remsg Packet as byte array
	 * @return Returns message without any additional data
	 */
	public byte[] deconstruct(byte[] remsg) {
		byte[] message = null;
		byte[] digest = null;
		boolean doContinue = false;
		try{
			ByteArrayInputStream byteStream = new ByteArrayInputStream(remsg);
			DataInputStream dataStream = new DataInputStream(byteStream);
			byte type = dataStream.readByte();
			int lengthMessage = dataStream.readInt();
			int lengthDigest = dataStream.readInt();
			message= new byte[lengthMessage];
			digest= new byte[lengthDigest];
			dataStream.read(message, 0, lengthMessage);
			dataStream.read(digest, 0, lengthDigest);
			dataStream.close();
			doContinue = this.evaluate(digest, cryptoParameters[2], message);
		}catch(Exception e){
			System.err.println("Caught an Exception while deconstructing message");
			System.err.println("getMessage():" + e.getMessage());
			System.err.println("getLocalizedMessage():" +e.getLocalizedMessage());
			System.err.println("toString():" + e);
			System.err.println("printStackTrace():");
			e.printStackTrace();
			throw new RuntimeException(e);
		}
		if(doContinue){return message;}
		else return null;

	}
	
	/* (non-Javadoc)
	 * @see Transmitter#send(byte[])
	 */
	public void send(byte[] semsg) throws IOException{
		if(semsg.length>maxSize){
			ByteArrayInputStream bytestream = new ByteArrayInputStream(semsg);
			for (int i = 0; i < semsg.length; i += maxSize) {	
				    int min= Math.min(maxSize, semsg.length - i);
				    byte[] separt = new byte[min];
					bytestream.read(separt, 0, min);
					super.send(this.construct(separt));}
		}else {
			super.send(this.construct(semsg));}
	}
	
	/* (non-Javadoc)
	 * @see Transmitter#receive()
	 */
	public byte[] receive() throws TransmissionException, IOException{
		byte[] remsg = null;
			remsg = super.receive();
			return this.deconstruct(remsg);
	}

	
	/**
	 * Compares the message digests - the received and new one calculated. Compares the message counters.
	 * @param digestData Received digest data with counter, still encrypted 
	 * @param key For decryption
	 * @param message The message that the digest will be calculated on
	 * @return Returns true if the packet contents passes the counter and digest test.
	 */
	public boolean evaluate(byte[] digestData, byte[] key, byte[] message){
		try{
			MessageDigest tempDigest = MessageDigest.getInstance("SHA-256");
			byte[] digestCounterDecrypted = this.rsaModify(digestData, key, 2);
			ByteArrayInputStream byteStream = new ByteArrayInputStream(digestCounterDecrypted);
			DataInputStream dataStream = new DataInputStream(byteStream);
			int remoteCounter = dataStream.readInt();
			int remoteDigestLength = dataStream.readInt();
			byte[] digestDecrypted = new byte[remoteDigestLength];
			dataStream.read(digestDecrypted, 0, remoteDigestLength);
			dataStream.close();
			byte[] digestNew = tempDigest.digest(message);
			System.out.println("Remote message counter: " + remoteCounter);
			System.out.println("Local message counter:  " + remoteCounter);
			System.out.println("Message digest from remote party:  " + DiffieHellman.byteArrayToHexString(digestDecrypted));
			System.out.println("Message digest calculated locally: " + DiffieHellman.byteArrayToHexString(digestNew));
			if(!Arrays.equals(digestDecrypted, digestNew)){throw new MessageTamperedException();}
			if(!this.evaluateCounter(remoteCounter)){throw new MessageReplayedException();}
		}catch(Exception e) 
				{
			      System.err.println("Caught an Exception while evaluating message contents");
			      System.err.println("getMessage():" + e.getMessage());
			      System.err.println("getLocalizedMessage():" +
			        e.getLocalizedMessage());
			      System.err.println("toString():" + e);
			      System.err.println("printStackTrace():");
			      e.printStackTrace();
			      throw new RuntimeException(e);
			}
		return true; 
	}
	
	/**
	 * Method used to compare the counters and keep track of the old one.
	 * @param newCounter Received counter
	 * @return Returns true if the new counter is legal
	 */
	public boolean evaluateCounter(int newCounter){
		if(lastCounter==(newCounter-1)){
			lastCounter=newCounter;
			return true;
		}else return false;
		
	}
	

}
