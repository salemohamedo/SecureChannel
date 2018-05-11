import java.math.BigInteger;
import java.util.Arrays;
import java.nio.ByteBuffer;
public class RSAKey {
    private BigInteger exponent;
    private BigInteger modulus;
    
    private static final int oaepK0SizeBytes = 32;
	private static final int oaepK1SizeBytes = 32;

    public RSAKey(BigInteger theExponent, BigInteger theModulus) {
        exponent = theExponent;
        modulus = theModulus;
    }

    public BigInteger getExponent() {
        return exponent;
    }

    public BigInteger getModulus() {
        return modulus;
    }

    public byte[] encrypt(byte[] plaintext, PRGen prgen) {
        if (plaintext == null)    throw new NullPointerException();
	if (plaintext.length > maxPlaintextLength()) return null;
	BigInteger tmp;
	//System.out.print("\nenc modulus =" + this.modulus);
	//System.out.print("\nenc exponent =" + this.exponent);
	//System.out.print("\noriginal plaintext length =" + plaintext.length + "\n");
	byte[] encode = encodeOaep(plaintext,prgen);
	//System.out.print("\nencrypt value before modpow and length =" + encode.length + "\n");
	//System.out.print(Arrays.toString(encode));
	//System.out.print("\n");
	BigInteger encode_BI = Proj2Util.bytesToBigInteger(encode);
	assert ((encode_BI.compareTo(modulus))<0);
	//	System.out.print("\n this is ur error omar \n");
	//	System.out.print(encode_BI.bitLength());
	//	System.out.print("\n");
	//	System.out.print(modulus.bitLength());
	//	System.out.print("\n");
	//}
	//System.out.print("\n Encode BI value =" + encode_BI + "\n");
	//BigInteger test5 = new BigInteger("5");
	//System.out.print("\n test 5 in big int looks like = " + test5 + "\n");
	//test5 = test5.modPow(this.exponent,this.modulus);
	//System.out.print("\nenc test5 =" + test5 + "\n");
	tmp = encode_BI.modPow(this.exponent,this.modulus);
	//System.out.print("\nenc tmp =" + tmp + "\n");
	//int tmp_bytes = tmp.toByteArray().length;
	//int len = maxPlaintextLength() + 5 + 32 + 32;
	//System.out.print("\nTmpBytes Encrypt = " + tmp_bytes +"len = " + len + "\n");
	//byte[] ret = Proj2Util.bigIntegerToBytes(tmp,tmp_bytes + 1);
        //System.out.print("\nencrypt after modpow length =" + ret.length + "\n");
	//System.out.print("\nEncrypt value after modpow\n");
	//System.out.print(Arrays.toString(ret));
	//System.out.print("\n");
	return tmp.toByteArray(); 
	//return encode_BI.toByteArray();
        // IMPLEMENT THIS
    }

    public byte[] decrypt(byte[] ciphertext) {
        if (ciphertext == null)    throw new NullPointerException();
	BigInteger tmp;
	//System.out.print("\nDec: Cipher Text Before Decryption and modpow\n");
	//System.out.print(Arrays.toString(ciphertext));
        //System.out.print("\n dec modulus = " + this.modulus);
	//System.out.print("\n dec exponent = " + this.exponent);
	//System.out.print("\nDec: Ciphertext before modpow length =" + ciphertext.length + "\n");
	BigInteger dec_cipher = Proj2Util.bytesToBigInteger(ciphertext);
	//System.out.print("\ndec_cipher bytes should equal enc tmp" + (dec_cipher.bitLength()/8) + "\n");
	tmp = dec_cipher.modPow(this.exponent,this.modulus);
	//int tmp_bytes = tmp.toByteArray().length;
	//int len = maxPlaintextLength() + 5 + 32 + 32;
	//System.out.print("\nTmpBytes Decrypt = " + tmp_bytes + "len = " + len + "\n");
	//int mult8 = 0;
	//if(((modulus.bitLength()/8)%8) == 0) mult8 = 1;
	byte[] prepare_text = Proj2Util.bigIntegerToBytes(tmp,(this.modulus.bitLength()/8)-1);
	//System.out.print("\nDecrypt after modpow, length = " + prepare_text.length + "\n");
	//System.out.print(Arrays.toString(prepare_text));
	byte[] ptext = decodeOaep(prepare_text);
        //System.out.print("\ndecrypt b4 modpow length =" + prepare_text.length + "\n");
	if(ptext == null){
		return null;}
	return ptext; 
//        return null; // IMPLEMENT THIS
    }

    public byte[] sign(byte[] message, PRGen prgen) {
        // Create a digital signature on <message>. The signature need
        //     not contain the contents of <message>--we will assume
        //     that a party who wants to verify the signature will already
        //     know which message this is (supposed to be) a signature on.
    	//
    	//     Note: The signature algorithm that we discussed in class is 
    	//     deterministic, and so if you implement it, you do not need 
    	//     to use the PRGen parameter. There is, however, a signature 
    	//     algorithm that is superior to the one that we discussed that 
    	//     does use pseudorandomness. Implement it for extra credit. See
    	//     the assignment description for details.
        if (message == null)    throw new NullPointerException();
	byte[] hash = new byte[oaepK0SizeBytes];
	hash = Proj2Util.hash(message);
	byte[] padded_hash = new byte[maxPlaintextLength()];
	//byte[] bigger_hash = new byte[256];
	//System.arraycopy(hash,0,bigger_hash,0,256);
	padded_hash = addPadding(hash);
	BigInteger padded_h_bytes = Proj2Util.bytesToBigInteger(padded_hash);
	BigInteger signature = padded_h_bytes.modPow(exponent,modulus);
		
        return signature.toByteArray(); // IMPLEMENT THIS
    }

    public boolean verifySignature(byte[] message, byte[] signature) {
        // Verify a digital signature. Returns true if  <signature> is
        //     a valid signature on <message>; returns false otherwise.
        //     A "valid" signature is one that was created by calling
        //     <sign> with the same message, using the other RSAKey that
        //     belongs to the same RSAKeyPair as this object.
        if ((message == null) || (signature == null))    throw new NullPointerException();
        byte[] hash = new byte[oaepK0SizeBytes];
        hash = Proj2Util.hash(message);
        byte[] padded_hash = new byte[maxPlaintextLength()];
	//System.arraycopy(hash,0,padded_hash,0,256);
        padded_hash = addPadding(hash);
        BigInteger padded_h_bytes = Proj2Util.bytesToBigInteger(padded_hash);
        //BigInteger calc_signature = padded_h_bytes.modPow(exponent,modulus);
	BigInteger giv_signature = Proj2Util.bytesToBigInteger(signature);
	BigInteger giv_sign_rss = giv_signature.modPow(exponent,modulus);
	boolean result = padded_h_bytes.equals(giv_sign_rss);
	
        return result; // IMPLEMENT THIS
    }

    public int maxPlaintextLength() {
        // Return the largest x such that any plaintext of size x bytes
        //      can be encrypted with this key
	
        //return ((modulus.bitLength()+1)/8)  - oaepK0SizeBytes - oaepK1SizeBytes - 4; // IMPLEMENT THIS
    	return (modulus.bitLength()/8) - oaepK0SizeBytes - oaepK1SizeBytes - 5;
	}
       
    // The next four methods are public to help us grade the assignment. In real life, these would
    // be private methods as there's no need to expose these methods as part of the public API
    
    public byte[] encodeOaep(byte[] input, PRGen prgen) {
	if(input.length > (maxPlaintextLength() + 1)){
		return null;
	}
        byte[] seed = new byte[oaepK0SizeBytes];
	prgen.nextBytes(seed);
	
	PRGen prg_g = new PRGen(seed);
	byte[] ptext = new byte[input.length];
	System.arraycopy(input,0,ptext,0,input.length);
//	System.out.print("\nunpadded message = " + ptext + "uml = " + ptext.length);
	ptext = addPadding(ptext);
	//System.out.print("\npml = " + ptext.length);
	//System.out.print("\nShould be equal encode right after padding\n");
	//System.out.print(Arrays.toString(ptext));
	//concat message w k0 0's
	byte[] padded_message = new byte[maxPlaintextLength() + 4 + oaepK1SizeBytes];
	System.arraycopy(ptext,0,padded_message,0,(maxPlaintextLength()+ 4));
	//Arrays.fill(padded_message,maxPlaintextLength() + 4, maxPlaintextLength() + 4 + oaepK1SizeBytes, (byte)(0));

	//System.out.print("\n should be same message but now 224 bytes long =" + padded_message.length + "\n");
	//System.out.print(Arrays.toString(padded_message));
		
	byte[] G = new byte[maxPlaintextLength() + oaepK0SizeBytes + 4];
	prg_g.nextBytes(G);
	byte[] X = new byte[maxPlaintextLength() + 4 + oaepK1SizeBytes];
	for(int i = 0; i < (maxPlaintextLength() +  4 + oaepK1SizeBytes); i++){
		X[i] = (byte)(padded_message[i] ^ G[i]);}
	//System.out.print("\n should still be 224 bytes long but has now been xored with G =" + X.length + "\n");
	//System.out.print(Arrays.toString(X));
	byte[] y_hash = new byte[oaepK0SizeBytes];
	y_hash = Proj2Util.hash(X,0,oaepK0SizeBytes);
	byte[] Y = new byte[oaepK0SizeBytes];
	for(int i = 0;i < oaepK0SizeBytes; i++){
		Y[i] = (byte)(seed[i] ^ y_hash[i]);}
	//System.out.print("\ny value, should be 32 = " + Y.length + "\n");
	//System.out.print(Arrays.toString(Y)); 
	byte[] X_Y = new byte[X.length + Y.length];
	System.arraycopy(X,0,X_Y,0,X.length);
	System.arraycopy(Y,0,X_Y,X.length,Y.length);
	//System.out.print("\n X and Y value combined, should be 256 bytes long =" + X_Y.length + "\n");
	//System.out.print(Arrays.toString(X_Y));
	return X_Y;
	
	
    }

    
    public byte[] decodeOaep(byte[] input) {
	//System.out.print("\ndecode input length = " + input.length + "\n");	
	byte[] X = new byte[maxPlaintextLength() + 4 +oaepK1SizeBytes];
	byte[] Y = new byte[oaepK1SizeBytes];
	System.out.print("\n in decode, input length, mplt, n length" + input.length + "\n" + maxPlaintextLength() + "\n" + modulus.bitLength()/8 + "\n");
	System.arraycopy(input,0,X,0,(maxPlaintextLength() + 4 + oaepK1SizeBytes));
	System.arraycopy(input,(maxPlaintextLength() + 4 + oaepK1SizeBytes),Y,0,oaepK1SizeBytes);
	byte[] y_hash = new byte[oaepK0SizeBytes];
	y_hash = Proj2Util.hash(X,0,oaepK0SizeBytes);

	//recover seed
	byte[] seed = new byte[oaepK0SizeBytes];
	for(int i = 0; i < oaepK0SizeBytes; i++){
		seed[i] = (byte)(Y[i] ^ y_hash[i]);}
	PRGen prg_g = new PRGen(seed);
	byte[] G = new byte[maxPlaintextLength() + 4 + oaepK1SizeBytes];
	prg_g.nextBytes(G);
	byte[] padded_message = new byte[maxPlaintextLength() + 5 + oaepK0SizeBytes];
	for(int i = 0; i < (maxPlaintextLength() + 4 + oaepK0SizeBytes ); i++){
		padded_message[i] = (byte)(G[i] ^ X[i]);}
	byte[] msg = new byte[input.length - oaepK0SizeBytes - oaepK1SizeBytes];
	System.arraycopy(padded_message,0,msg,0,input.length - oaepK0SizeBytes - oaepK1SizeBytes);
	//System.out.print("decode padded_message length b4 padding removal =" + padded_message.length);	
	//System.out.print("mpltl in decode is = " + maxPlaintextLength());
	//System.out.print("\nshould be equal 2 length is =" + msg.length + "\n");
	//System.out.print(Arrays.toString(msg));
	return removePadding(msg);
         // IMPLEMENT THIS
    }
    
 

    public byte[] addPadding(byte[] input){
	//checks if input is n - k0 - k1 long
	int maxlen = maxPlaintextLength();
	assert (input.length < maxlen + 1);
	//System.out.print("\n inside addPadding inputlength =" + input.length + "\n");
//	System.out.print("\n inside addPadding check =" + check + "\n");
	byte[] padded = new byte[maxlen + 4];
	System.arraycopy(input,0,padded,0,input.length);
	//padded[check - 1] = (byte)(check - input.length);
	//int test = check - input.length;
	//int test2 = (int) padded[check - 1];
	//System.out.print("test 2 this should be 190=" + test2);
	//System.out.print("test should be 190 =" + test);
	//byte test3 = padded[check-1];
	//System.out.print("\ntest 3 value =" + test3);
	//System.out.print("\nthis value should be 190 =" + ((int) (padded[check-1])) + "\n");
	int amount_pad = maxPlaintextLength() - input.length ;
	byte[] padlen = ByteBuffer.allocate(4).putInt(amount_pad).array();
	//System.out.print("\n ammount padded here is = " + amount_pad);
	System.arraycopy(padlen,0,padded,maxPlaintextLength(),4);
	//System.out.print("\n padding length should be 188, it is =" + padded.length);
	return padded;
        //return null; // IMPLEMENT THIS
    }

   public byte[] removePadding(byte[] input) {
        //int check = maxPlaintextLength() + 1;
        //System.out.print("\n");
        //System.out.print("check value" + check);
//      System.out.print("mpl value" + maxPlaintextLength());
        //System.out.print("\n");
//        assert (input.length == (maxPlaintextLength() + 1));
        //System.out.print("\nhere\n");
        //System.out.print(input);
        //System.out.print("remove padding rnput length" + input.length);
        byte[] padlen = new byte[4];
        System.arraycopy(input,maxPlaintextLength(),padlen,0,4);
        //System.out.print("msg index" + msg_index);
        //byte[] original_msg = new byt
//      int paddedamount = padlen[0] << 24 | (padlen[1] & 0xff) << 16 | (padlen[2] & 0xff) <<8 | (padlen[3] & 0xff);
        //System.arraycopy(input,0,msg,0,check - msg_index);
        //System.out.print("\n decoded message length before returning Decrypt = " + msg.length + "\n");
        int paddedamount = ByteBuffer.wrap(padlen).getInt();
        //System.out.print("\n 2padded amount here is = " + paddedamount + "\n");
        byte[] original_msg = new byte[maxPlaintextLength() - paddedamount];
//      System.out.print("\n padded amount here is = " + paddedamount + "\n");
        System.arraycopy(input,0,original_msg,0,(maxPlaintextLength() - paddedamount));

        return original_msg;

         // IMPLEMENT THIS
    }

    
 


//	public static void main(String[] args){

//		byte[] arr1 = new byte[32];
//		for(int i = 0; i<16; i++){
//			arr1[i] = (byte)i;
//		}
//		byte[] arr2 = new byte[32];
//		for(int i = 0; i < 18; i++){
//			arr2[i] = (byte)i;}
//		PRGen prg = new PRGen(arr1);
//		PRGen prg2 = new PRGen(arr2);
//		RSAKeyPair rsakp = new RSAKeyPair(prg,768);
//		RSAKey pub = rsakp.getPublicKey();
//		int mkpl = pub.maxPlaintextLength();
//		RSAKey pri = rsakp.getPrivateKey();
		//byte[] msg = new byte[pub.maxPlaintextLength()-20];
		//prg.nextBytes(msg);
//		byte[] msg = new byte[mkpl];
//		for(int i = 0; i < mkpl; i++){
//			msg[i] = (byte)(0x0);
//		}
		//msg[0] = (byte)(0x0);
		//prg.nextBytes(arr2);
///		byte[] cipher = pub.encrypt(msg,prg);
//		System.out.print("mpltl = " + pub.maxPlaintextLength());
//		System.out.print("\n Cipher text is: \n");
//		System.out.print(Arrays.toString(cipher));
//		byte[] dec_msg = pri.decrypt(cipher);
//		System.out.print("\n");
//		System.out.print("\ninput plaintext = " + Arrays.toString(msg));
//		System.out.print("\n");
//		System.out.print(Arrays.toString(cipher));
//		System.out.print("\n");
//		System.out.print("\noutput plaintext = " + Arrays.toString(dec_msg));
//		System.out.print("\noriginal message length = " + msg.length + "\n");
//		System.out.print("\ndecoded message length = " + dec_msg.length + "\n");
		
		
    //            PRGen prg3 = new PRGen(arr1);
  //              PRGen prg4 = new PRGen(arr2);
//		RSAKeyPair rsakp2 = new RSAKeyPair(prg3,1024);
  //              BigInteger p = rsakp2.getPrimes()[0];
//                BigInteger q = rsakp2.getPrimes()[1];
//                RSAKey pub2 = rsakp2.getPublicKey();
  //              RSAKey pri2 = rsakp2.getPrivateKey();

//		boolean result;
//		byte[] signature = pri2.sign(msg,prg4);
//		result = pub2.verifySignature(msg,signature);
//		System.out.print("\n this should be true, it is = " + result + "\n");
		

		
//		}
}
