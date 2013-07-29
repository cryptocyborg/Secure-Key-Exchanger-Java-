import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;



/**	
	
* The class doing the actual encryption
 
*@author Ilesanmi Olufemi Olajide
*/


public class kthSecure {
			
		public byte[] EncryptMessage (byte[] msg) throws NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, ShortBufferException, IllegalBlockSizeException, BadPaddingException, IllegalStateException
	 {
		IvParameterSpec ivSpec=  new IvParameterSpec("0000046760601514".getBytes());
	    byte[] sharedKeyBytes = "0000046760601514".getBytes();
	    Key key = new SecretKeySpec(sharedKeyBytes,"AES");
	    Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
	    String input = new String(msg);
	    Mac mac = Mac.getInstance("hmacsha1");
	    byte[] macKeyBytes = "12345678".getBytes();
	    Key macKey = new SecretKeySpec(macKeyBytes, "DES");
	  
	    // encryption step
	    cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
	    byte[] cipherText = new byte[cipher.getOutputSize(input.length() + mac.getMacLength())];
	    int ctLength = cipher.update(input.getBytes(), 0, input.length(), cipherText, 0);
	    mac.init(macKey);
	    mac.update(input.getBytes());
	    byte[] harshe = mac.doFinal();
	    System.out.println(new String(input));
	    System.out.println(new String(harshe));
	    ctLength += cipher.doFinal(harshe, 0, mac.getMacLength(), cipherText, ctLength);
	    System.out.println("cipherText : " + new String(cipherText));
		
		return cipherText; 
	 }
		
	
	public byte[] DecryptMessage (byte[] mgsCipher) throws NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, ShortBufferException, IllegalBlockSizeException, BadPaddingException, IllegalStateException
	 {
		System.out.println(new String(mgsCipher));
		IvParameterSpec ivSpec=  new IvParameterSpec("0000046760601514".getBytes());
	    byte[] sharedKeyBytes = "0000046760601514".getBytes();
	    Key key = new SecretKeySpec(sharedKeyBytes,"AES");
	    Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
	    Mac mac = Mac.getInstance("hmacsha1");
	    byte[] macKeyBytes = "12345678".getBytes();
	    Key macKey = new SecretKeySpec(macKeyBytes, "DES");
	    
	    cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);
	    byte[] DecipheredText = cipher.doFinal(mgsCipher, 0,mgsCipher.length);
	    System.out.println(new String(DecipheredText));
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
	    
	    return plainText;	
	 }
	
	
		
}
