import java.math.BigInteger;
import java.util.Arrays;
public class KeyExchange {
	
	public static final int OutputSizeBytes = Proj2Util.HashSizeBytes;
	public static final int OutputSizeBits = Proj2Util.HashSizeBits;
	public static BigInteger g;
	public static BigInteger p;
	public static BigInteger a;
	public KeyExchange(PRGen rand) {
		// Prepares to do a key exchange. rand is a secure pseudorandom generator
		//    that can be used by the implementation.
		//
		// Once the KeyExchange object is created, two operations have to be performed to complete
		// the key exchange:
		// 1.  Call prepareOutMessage on this object, and send the result to the other
		//     participant.
		// 2.  Receive the result of the other participant's prepareOutMessage, and pass it in
		//     as the argument to a call on this object's processInMessage.  
		// For a given KeyExchange object, prepareOutMessage and processInMessage
		// could be called in either order, and KeyExchange should produce the same result regardless.
		//
		// The call to processInMessage should behave as follows:
		//     If passed a null value, then throw a NullPointerException.
		//     Otherwise, if passed a value that could not possibly have been generated
		//        by prepareOutMessage, then return null.
		//     Otherwise, return a "digest" value with the property described below.
		//
		// This code must provide the following security guarantee: If the two 
		//    participants end up with the same non-null digest value, then this digest value
		//    is not known to anyone else.   This must be true even if third parties
		//    can observe and modify the messages sent between the participants.
		// This code is NOT required to check whether the two participants end up with
		//    the same digest value; the code calling this must verify that property.

		// IMPLEMENT THIS
		byte[] a_bytes = new byte[32];
		rand.nextBytes(a_bytes);
		this.a = Proj2Util.bytesToBigInteger(a_bytes);
//		System.out.print("\n OutputSizeBytes = " + OutputSizeBytes + "a length" + a_bytes.length + "\n");
	}

	public byte[] prepareOutMessage() {
		this.g = DHParams.g;
		this.p = DHParams.p;
		BigInteger out = g.modPow(a,p);
//		System.out.print(out.toByteArray().length);
		byte[] out_bytes = Proj2Util.bigIntegerToBytes(out,OutputSizeBytes);
		
		return out_bytes; // IMPLEMENT THIS
	}


	public byte[] processInMessage(byte[] inMessage) {
		if (inMessage.length != OutputSizeBytes) return null;
		if (inMessage == null)    throw new NullPointerException();
		BigInteger inM_BI = Proj2Util.bytesToBigInteger(inMessage);
		BigInteger mod_in = inM_BI.modPow(this.a,this.p);
		byte[] in_bytes = new byte[OutputSizeBytes];
		in_bytes = Proj2Util.bigIntegerToBytes(mod_in,OutputSizeBytes);
		return Proj2Util.hash(in_bytes);
		//return null; // IMPLEMENT THIS
	}


//	public static void main(String[] args){
//		
//	byte[] key1 = new byte[8];
//	byte[] key2 = new byte[8];

//	for(int i = 0; i < 8; i++){
//		key1[i] = (byte)(i+5);
//		key2[i] = (byte)i;}
//	PRGen prg1 = new PRGen(key1);
//	PRGen prg2 = new PRGen(key2);

//	KeyExchange ke1 = new KeyExchange(prg1);
//	KeyExchange ke2 = new KeyExchange(prg2);
	
//	byte[] out1 = ke1.prepareOutMessage();
//	byte[] out2 = ke2.prepareOutMessage();

//	byte[] proc1 = ke1.processInMessage(out2);
//	byte[] proc2 = ke2.processInMessage(out1);

//	System.out.print("\n these keys should be equal\n");
//	System.out.print("\nProc 1\n");
//	System.out.print(Arrays.toString(proc1));
//	System.out.print("\nProc 2\n");
//	System.out.print(Arrays.toString(proc2));
	
//	}
}		
