import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Random;

/**
 * Implementation of the Diffie-Hellman key agreement and key generation
 * according to urn:ietf:rfc:2631 (http://tools.ietf.org/html/rfc2631)
 * 
 * @author Thomas Riedmaier
 * 
 */
public class DiffieHellman {

	// For more keys see
	// http://bent.latency.net/bent/git/dumpasn1/src/dumpasn1.cfg
	public static String aes128_CBC = "06 09 60 86 48 01 65 03 04 01 02";
	public static String cms3DESwrap = "06 0b 2a 86 48 86 f7 0d 01 09 10 03 06";
	public static String hmacWithSHA1 = "06 08 2A 86 48 86 F7 0D 02 07";
	public static String desMAC = "06 05 2B 0E 03 02 0A";

	/**
	 * Generate 160 bit of keying material
	 * 
	 * @param sharedSecret
	 *            : The result of the DH-Key agreement
	 * @param keyOID
	 *            : some examples are given in this file - for more see
	 *            http://bent.latency.net/bent/git/dumpasn1/src/dumpasn1.cfg
	 * @param counterVal
	 *            : if the desired key is longer than 160 bits: increment
	 *            counter and append higher counter result at the end of the
	 *            lower counter result
	 * @param keylength
	 *            : length of the key that will be generated (e.g. 3DES has 192)
	 * @return 160 bits of keying material
	 */
	public static byte[] genKM(byte[] sharedSecret, String keyOID, int counterVal, int keylength) {
		byte[] kOID = hexStringToByteArray(keyOID);
		byte[] input = new byte[sharedSecret.length + kOID.length + 18];

		int i = 0;
		for (; i < sharedSecret.length; i++)
			input[i] = sharedSecret[i];
		
		input[i++] = 0x30;
		input[i++] = 0x1d;
		input[i++] = 0x30;
		input[i++] = 0x13;
		
		for (int j = i; i - j < kOID.length; i++)
			input[i] = kOID[i - j];
		
		input[i++] = 0x04;
		input[i++] = 0x04;

		input[i++] = (byte) (counterVal >> 24);
		input[i++] = (byte) (counterVal >> 16);
		input[i++] = (byte) (counterVal >> 8);
		input[i++] = (byte) (counterVal);

		input[i++] = -94;
		input[i++] = 0x06;
		input[i++] = 0x04;
		input[i++] = 0x04;

		input[i++] = (byte) (keylength >> 24);
		input[i++] = (byte) (keylength >> 16);
		input[i++] = (byte) (keylength >> 8);
		input[i++] = (byte) (keylength);

		MessageDigest md = null;
		try {
			md = MessageDigest.getInstance("SHA-1");
		} catch (NoSuchAlgorithmException e) {
			System.err.println("This system doesn't support SHA-1");
			System.exit(0);
		}

		return md.digest(input);
	}

	/**
	 * Generates the sharedSecret value aka "ZZ"
	 * 
	 * @param ownPrivate
	 * @param otherPublic
	 * @param p
	 * @param pBits
	 *            : length of the prime p in bits. This length might differ from
	 *            the amount of bits the BigNumber representation uses
	 * @return ZZ
	 */
	public static byte[] generateSharedSecret(BigInteger ownPrivate, BigInteger otherPublic, BigInteger p, int pBits) {
		BigInteger sharedSecret = otherPublic.modPow(ownPrivate, p);
		byte[] sSecret = sharedSecret.toByteArray();

		byte[] re = new byte[(int) Math.ceil(pBits / 8.)];
		System.arraycopy(sSecret, Math.max(0, sSecret.length - re.length), re, Math.max(0, re.length - sSecret.length), Math.min(sSecret.length, re.length));
		return re;
	}

	/**
	 * Generates two larges Primes {p, q} according to RFC 2631 section-2.2
	 * 
	 * @param pBits
	 *            : length of p in bits (at least 512)
	 * @param qBits
	 *            : length of q in bits (at least 160)
	 * @param certainty
	 *            : How certain does it have to be that p and q are prime? p and
	 *            q are prime with a probability that exceeds (1 -
	 *            1/2^certainty)
	 * @return {p, q}
	 * @throws IllegalArgumentException
	 */
	public static BigInteger[] genPQ(int pBits, int qBits, int certainty) throws IllegalArgumentException {

		if (pBits < 512)
			throw new IllegalArgumentException("p is required to have at least 512 bits (rfc2631)");
		if (qBits < 160)
			throw new IllegalArgumentException("q is required to have at least 160 bits (rfc2631)");

		MessageDigest md = null;
		try {
			md = MessageDigest.getInstance("SHA-1");
		} catch (NoSuchAlgorithmException e) {
			System.err.println("This system doesn't support SHA-1");
			System.exit(0);
		}

		BigInteger p, q;

		// Step 1
		int ms = (int) Math.ceil((double) qBits / 160.);

		// Step 2
		int Ls = (int) Math.ceil((double) pBits / 160.);

		// Step 3
		int Ns = (int) Math.ceil((double) pBits / 1024.);

		Random rnd = new SecureRandom();
		byte[] SEEDB = new byte[(int) Math.ceil(qBits / 8.)];
		BigInteger SEED = null;
		while (true) {

			// Step 4
			rnd.nextBytes(SEEDB);

			// Step 5
			BigInteger U = new BigInteger("0");

			// Step 6
			for (int i = 0; i < ms; i++) {
				SEED = new BigInteger(SEEDB);
				BigInteger tmp1 = SEED.add(new BigInteger(String.valueOf(i)));
				BigInteger tmp2 = SEED.add(new BigInteger(String.valueOf(ms + i)));

				BigInteger tmp4 = new BigInteger(md.digest(tmp1.toByteArray()));
				BigInteger tmp5 = new BigInteger(md.digest(tmp2.toByteArray()));
				U = U.add(tmp4.xor(tmp5).shiftLeft(160 * i));
			}

			// Step 7
			q = U.mod(BigInteger.ONE.shiftLeft(qBits));
			q = q.or(BigInteger.ONE.shiftLeft(qBits - 1));
			q = q.or(BigInteger.ONE);

			// Step 8
			if (q.isProbablePrime(certainty))
				break;
		}

		// Step 9
		int counter = 0;
		do {
			int offset = 2 * ms + Ls * counter;

			// Step 10
			BigInteger R = SEED.add(new BigInteger(String.valueOf(offset)));

			// Step 11
			BigInteger V = new BigInteger("0");

			// Step 12
			for (int i = 0; i < Ls; i++) {
				BigInteger tmp1 = R.add(new BigInteger(String.valueOf(i)));
				BigInteger tmp4 = new BigInteger(md.digest(tmp1.toByteArray()));
				V = V.add(tmp4.shiftLeft(160 * i));
			}

			// Step 13
			BigInteger W = V.mod(BigInteger.ONE.shiftLeft(pBits));

			// Step 14
			BigInteger X = W.or(BigInteger.ONE.shiftLeft(pBits - 1));

			// Step 15
			BigInteger tmp1 = q.add(q);
			p = X.subtract(X.mod(tmp1));
			p = p.add(BigInteger.ONE);

			// Step 16
			if (p.compareTo(BigInteger.ONE.shiftLeft(pBits - 1)) == 1) {
				if (p.isProbablePrime(certainty)) {
					return new BigInteger[] { p, q };
				}
			}

			// Step 18
			counter++;
		}
		// Step 19
		while (counter < (4096 * Ns));

		System.err.println("Attempt to generate p and q failed!");
		return null;
	}

	/**
	 * Generates g according to RFC 2631 section-2.2: g = h^{(p-1)/q} mod p,
	 * where h is any integer with 1 < h
	 * < p-1 such that h{(p-1)/q} mod p >
	 * 1 (g has order q mod p; i.e. g^q mod p = 1 if g!=1) j a large integer
	 * such that p=qj + 1 (j>=2)
	 * 
	 * @param p
	 * @param q
	 * @return g
	 */
	public static BigInteger genG(BigInteger p, BigInteger q) {
		// Step 1
		BigInteger j = p.subtract(BigInteger.ONE).divide(q);

		Random rnd = new Random();
		BigInteger g, h;
		do {
			// Step 2
			do {
				h = new BigInteger(p.bitCount(), rnd);
			} while (h.compareTo(p.subtract(BigInteger.ONE)) != -1 || h.compareTo(BigInteger.ONE) != 1);

			// Step 3
			g = h.modPow(j, p);

		}
		// Step 4
		while (g.compareTo(BigInteger.ONE) == 0);

		return g;
	}

	/**
	 * Generates the keypair according to RFC 2631:
	 * 
	 * @param p
	 * @param q
	 *            : required since X9.42 requires the private key x to be in the
	 *            interval [2, (q - 2)]
	 * @param g
	 * @return {private, public}
	 */
	public static BigInteger[] genKeyPair(BigInteger p, BigInteger q, BigInteger g) {

		Random rnd = new Random();
		BigInteger x;
		do {
			x = new BigInteger(q.bitLength()+1, rnd);
		} while (x.compareTo(q.subtract(BigInteger.ONE.shiftLeft(1))) != -1 || x.compareTo(BigInteger.ONE.shiftLeft(1)) != 1);

		BigInteger y = g.modPow(x, p);
		return new BigInteger[] { x, y };
	}

	// copied from http://stackoverflow.com/questions/140131/convert-a-string-representation-of-a-hex-dump-to-a-byte-array-using-java
	/**
	 * Translate a string representation of a byte array to byte[]
	 * 
	 * @param s
	 *            : e.g. "06 09 60 86 48 01 65 03 04 01 2A"
	 * @return
	 */
	public static byte[] hexStringToByteArray(String s) {
		s = s.replace(" ", "");
		int len = s.length();
		byte[] data = new byte[len / 2];
		for (int i = 0; i < len; i += 2) {
			data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4) + Character.digit(s.charAt(i + 1), 16));
		}
		return data;
	}

	// copied from http://www.java2s.com/Code/Java/Data-Type/byteArrayToHexString.htm
	// (only used for debugging)
	/**
	 * Generate a printable String-representation of a byte[]
	 * 
	 * @param b
	 * @return
	 */
	public static String byteArrayToHexString(byte[] b) {
		StringBuffer sb = new StringBuffer(b.length * 2);
		for (int i = 0; i < b.length; i++) {
			int v = b[i] & 0xff;
			if (v < 16) {
				sb.append('0');
			}
			sb.append(Integer.toHexString(v));
		}
		return sb.toString().toUpperCase();
	}
}