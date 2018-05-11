import java.math.BigInteger;

public class RSAKeyPair {
	private RSAKey publicKey;
	private RSAKey privateKey;
	private BigInteger p;
	private BigInteger q;

	public RSAKeyPair(PRGen rand, int numBits) {
		// Create an RSA key pair.  rand is a PRGen that this code can use to get pseudorandom
		//     bits.  numBits is the size in bits of each of the primes that will be used.

		// IMPLEMENT THIS
		BigInteger n;
		BigInteger e;
		BigInteger d;
		BigInteger tmp;
		BigInteger zero;
		zero = BigInteger.ZERO;
		p = Proj2Util.generatePrime(rand, numBits);
		q = Proj2Util.generatePrime(rand, numBits);
		n = p.multiply(q);
//		System.out.print("\nn bit length =" + n.bitLength() + "\n");
		BigInteger relative = (p.subtract(BigInteger.ONE)).multiply(q.subtract(BigInteger.ONE));
		String[] e_options = {"65537","69119","70079","75011","86017","99881","1044327","103087","111191","169129","199489","246277","293213","317609","395303","438533","510233"};
		e = new BigInteger(e_options[0]);
                while (((relative.gcd(e)).compareTo(BigInteger.ONE) != 0)) { 
                        e = e.nextProbablePrime();                          
                }
                d = e.modInverse(relative);
//                assert (BigInteger.ONE.compareTo(e.multiply(d).mod(relative)) != 0);
                     
                        
                
		//System.out.print("e =" + e);	
		//System.out.print("d = " + d);
		publicKey = new RSAKey(e,n);
		privateKey = new RSAKey(d,n);
		
	}

	public RSAKey getPublicKey() {
		return publicKey;
	}

	public RSAKey getPrivateKey() {
		return privateKey;
	}

	public BigInteger[] getPrimes() {
		// Returns an array containing the two primes that were used in key generation.
		//   In real life we don't always keep the primes around.
		//   But including this helps us grade the assignment.
		BigInteger[] ret = new BigInteger[2];
		ret[0] = p; // IMPLEMENT THIS
		ret[1] = q;
		return ret;
	}
	
//	public static void main(String[] args){
//		byte[] key = new byte[32];
//		PRGen prg = new PRGen(key);
//		RSAKeyPair rsakp = new RSAKeyPair(prg,1024);
//		byte[] key2 = new byte[32];
//		for(int i = 0; i < 32; i++){
//			key2[i] = (byte)i;}
//		PRGen prg2 = new PRGen(key2);
	//	RSAKeyPair rsakp2 = new RSAKeyPair(prg,512);
		
	//	BigInteger p = rsakp.getPrimes()[0];
	//	BigInteger q = rsakp.getPrimes()[1];
	//	BigInteger e = rsakp.getPublicKey().getExponent();
	//	BigInteger d = rsakp.getPrivateKey().getExponent();
	//	BigInteger ed = e.multiply(d);
	//	BigInteger mod = ed.mod((p.subtract(BigInteger.ONE)).multiply((q.subtract(BigInteger.ONE))));
           //     BigInteger p2 = rsakp2.getPrimes()[0];
         //       BigInteger q2 = rsakp2.getPrimes()[1];
     //           BigInteger e2 = rsakp2.getPublicKey().getExponent();
       //         BigInteger d2 = rsakp2.getPrivateKey().getExponent();
    //            BigInteger ed2 = e2.multiply(d2);
  //              BigInteger mod2 = ed2.mod((p2.subtract(BigInteger.ONE)).multiply((q2.subtract(BigInteger.ONE))));

//		System.out.print("\n mod1 =" + mod + " mod2 = " + mod2);
//		}
}
