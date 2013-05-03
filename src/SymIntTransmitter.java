import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.InetAddress;
import java.net.SocketException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;


/**
*	This class implements a simple messsage exchange mechanism based on Shared key encryption.
	The packets constructed are based on the following structures:
* 	1. SHA-1 message digest was used to MAC(Message Authentistic Code 	Implementation) the packets
*	2. Actual message encryption was carried out using AES Shared 	Secret Keys between the two parties.
*	3. Message verification is carried out on every packet upon 	arrival.
*
*@author Ilesanmi Olufemi Olajide
*/


public class SymIntTransmitter extends Transmitter 
{
	byte[][] cryptoParameters = null;
		
	/**
	 * @param CryptoParameters
	 * @param otherIP
	 * @param otherPort
	 * @param ownPort
	 * @param maxMessageSize
	 * @throws SocketException
	 */
	
	public SymIntTransmitter(byte[][] CryptoParameters, InetAddress otherIP,int otherPort, int ownPort, int maxMessageSize)	throws SocketException 
	{
		super(CryptoParameters, otherIP, otherPort, ownPort, maxMessageSize);
		this.cryptoParameters= CryptoParameters;
		
	}

	/*
	 * (non-Javadoc)
	 * @see Transmitter#send(byte[])
	 */
	
	public void send(byte[] msg) throws IOException 
	{
		
		try 
			{
				
				int maxSize = maxMessageSize -256;//makes room for the payload
				
					if(msg.length>maxSize)
					{
						System.out.println("***Encrypting***");
						System.out.println("NOTE: large data detected. therefore will be broken done into several packets");
						ByteArrayInputStream bytestream = new ByteArrayInputStream(msg);
						for (int i = 0; i < msg.length; i += maxSize) 
						{	
							  	int min= Math.min(maxSize, msg.length - i);
						    	byte[] Fragment = new byte[min];
						    	bytestream.read(Fragment, 0, min);
						    	super.send(aesProcessData(Fragment,cryptoParameters[0],cryptoParameters[1],kthCipher.Encrypt));
						 }
					}
							
					else 
					{
						System.out.println("***Encrypting***");
						super.send(aesProcessData(msg,cryptoParameters[0],cryptoParameters[1],kthCipher.Encrypt));
					}
			} 
		catch (Exception e) 
			{
				System.err.println("Caught an Exception while processing data to be sent");
				System.err.println("getMessage():" + e.getMessage());
				e.printStackTrace();
			}
		
	}
	
	/*
	 * (non-Javadoc)
	 * @see Transmitter#receive()
	 */
	
	public byte[] receive() throws TransmissionException, IOException 
	{
			try {
					return aesProcessData(super.receive(),cryptoParameters[0],cryptoParameters[1],kthCipher.Decrypt);
				} 
			catch (InvalidKeyException e) 
				{
					System.err.println("+++ Invalid Key processing +++");
					e.printStackTrace();
				} 
			catch (NoSuchAlgorithmException e) 
				{
					System.err.println("+++ Invalid Algorithm attempted +++");
					e.printStackTrace();
				} 
			catch (NoSuchProviderException e) 
				{
					System.err.println("+++ Provider not available +++");
					e.printStackTrace();
				} 
			catch (NoSuchPaddingException e) 
				{
					System.err.println("+++ Invalid padding attempted +++");
					e.printStackTrace();
				} 
			catch (InvalidAlgorithmParameterException e) 
				{
					System.err.println("+++ Invalid Algorithm Parameter Supplied+++");
					e.printStackTrace();
				} 	
			catch (ShortBufferException e) 
				{
					System.err.println("+++ Buffer Shortage +++");
					e.printStackTrace();
				} 
			catch (IllegalBlockSizeException e) 
				{
					System.err.println("+++ Invalid BlockSize +++");
					e.printStackTrace();
				} 
			catch (BadPaddingException e) 
				{
					System.err.println("+++ Padding fault +++");
					e.printStackTrace();
				} 
			catch (IllegalStateException e) 
				{
					System.err.println("+++ Invalid State +++");
					e.printStackTrace();
				} 
			catch (InvalidKeySpecException e) 
				{
					System.err.println("+++ Invalid Key Specification +++");
					e.printStackTrace();
				}

			return null;
	}
	
	/**
	 * Encrypts the data
	 * @param msg Data to be encrypted
	 * @param sharedKeyBytes key used for encryption
	 * @param macKeyBytes key used to MAC the data for verification purposes
	 * @return Encrypted/MAC data is returned
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchProviderException
	 * @throws NoSuchPaddingException
	 * @throws InvalidKeyException
	 * @throws InvalidAlgorithmParameterException
	 * @throws ShortBufferException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 * @throws IllegalStateException
	 */
	
	public byte[] EncryptMessage (byte[] msg,byte[] sharedKeyBytes,byte[] macKeyBytes) throws NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, ShortBufferException, IllegalBlockSizeException, BadPaddingException, IllegalStateException
	 {
			IvParameterSpec ivSpec=  new IvParameterSpec(sharedKeyBytes);
		    Key key = new SecretKeySpec(sharedKeyBytes,"AES");
		    Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
		    String input = new String(msg);
		    Mac mac = Mac.getInstance("hmacsha1");
		    Key macKey = new SecretKeySpec(macKeyBytes, "DES");

		  
		    // actual encryption point
		    cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
		    byte[] cipherText = new byte[cipher.getOutputSize(input.length() + mac.getMacLength())];
		    int ctLength = cipher.update(input.getBytes(), 0, input.length(), cipherText, 0);
		    mac.init(macKey);
		    mac.update(input.getBytes());
		    byte[] harshe = mac.doFinal();
		    ctLength += cipher.doFinal(harshe, 0, mac.getMacLength(), cipherText, ctLength);
		    System.out.println("cipherText : " + new String(cipherText));
			
			return cipherText; //Encrypted data is returned
	 }
	
	/**
	 * Decrypts the data
	 * @param mgsCipher Data to be decrypted
	 * @param sharedKeyBytes key used for decryption
	 * @param macKeyBytes key used for data verification(MAC)
	 * @return Decrypted data---- further states if its been compromised or still secure
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchProviderException
	 * @throws NoSuchPaddingException
	 * @throws InvalidKeyException
	 * @throws InvalidAlgorithmParameterException
	 * @throws ShortBufferException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 * @throws IllegalStateException
	 */
	
 public byte[] DecryptMessage (byte[] mgsCipher,byte[] sharedKeyBytes,byte[] macKeyBytes) throws NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, ShortBufferException, IllegalBlockSizeException, BadPaddingException, IllegalStateException
 {
		IvParameterSpec ivSpec=  new IvParameterSpec(sharedKeyBytes);
	    Key key = new SecretKeySpec(sharedKeyBytes,"AES");
	    Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
	    Mac mac = Mac.getInstance("hmacsha1");
	    Key macKey = new SecretKeySpec(macKeyBytes, "DES");
	    
	    // actual decryption point
	    cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);
	    byte[] DecipheredText = cipher.doFinal(mgsCipher, 0,mgsCipher.length);
	    int messageLength = DecipheredText.length - mac.getMacLength();
	    mac.init(macKey);
	    byte[] plainText = new byte [messageLength];
	    System.arraycopy(DecipheredText, 0, plainText, 0, messageLength);
	    mac.update(plainText);
	    byte[] harshe = mac.doFinal();
	    byte[] messageHash = new byte[mac.getMacLength()];
	    System.arraycopy(DecipheredText, messageLength, messageHash, 0, messageHash.length);
	    System.out.println("plain : " + new String(plainText) + " verified: "
	            + MessageDigest.isEqual(harshe, messageHash));
	    
	    return plainText;	//Plain text data is returned
 }
 

 /**
	 * Encrypts or decrypts input
	 * @param msg Data to be encrypted/decrypted
	 * @param sharedKeyBytes key used for encryption/decryption
	 * @param macKeyBytes key used for data verification(MAC)
	 * @param mode see kthCipher enumeration  
	 * @return Encrypted or Decrypted data is returned
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 * @throws InvalidKeySpecException
	 * @throws InvalidKeyException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 * @throws NoSuchProviderException
	 * @throws InvalidAlgorithmParameterException
	 * @throws ShortBufferException
	 * @throws IllegalStateException
	 */
 
 public byte[] aesProcessData(byte[] msg, byte[] sharedKey, byte[] macKey, kthCipher mode) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeySpecException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchProviderException, InvalidAlgorithmParameterException, ShortBufferException, IllegalStateException  
 		{
		
			switch (mode) 
				{
					case Encrypt: //System.out.println("***Encrypting***");
									
							return EncryptMessage(msg,sharedKey,macKey);
					
					case Decrypt: System.out.println("***Decrypting***");
								
							return DecryptMessage(msg,sharedKey,macKey);
						     
					case Neutral: System.out.println("********************");
						     //future implementation
							return null;
				    
					default:
							return null;
				}
		}
 
 	/**
 	 * kthCipher
	 * Enumeration class used to cipher mode
	 * Get and Set properties exposed
	 * 	 */
 
 public enum kthCipher 
 	{
		 Encrypt(1),Decrypt(2),Neutral(0);  //; cipher mode options
		 private final int mode;// 
		
			 kthCipher(int mode)// Enum Set method
			 {
				   this.mode = mode;
			 }
			 
			 public int mode() // Enum Get method
			 { 
				 return mode; 
			 }
	}
 
 
 
 
}
