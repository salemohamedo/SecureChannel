//import java.util.Arrays;

public class StreamCipher implements Proj1Constants {
	// This class encrypts or decrypts a stream of bytes, using a stream cipher.
	
	private PRGen prg;
	private byte[] seed;
	private byte[] nonce;


	public StreamCipher(byte[] key) {
		// <key> is the key, which must be KeySizeBytes bytes in length.

		assert key.length == KeySizeBytes;
		//initialize the StreamCipher with the given key.
		this.seed = key;
		//prg = new PRGen(key);
		

		// IMPLEMENT THIS
	}

	public void setNonce(byte[] arr, int offset){
		// Reset to initial state, and set a new nonce.
		// The nonce is in arr[offset] thru arr[offset+NonceSizeBytes-1].		
		// It is an error to call setNonce with the same nonce
		//    more than once on a single StreamCipher object.
		// StreamCipher does not check for nonce uniqueness;
		//    that is the responsibility of the caller.

	//	if(arr.length != (NonceSizeBytes + offset)){
		//	throw new Exception("Nonce Size not in array");
		//}
		//make sure Nonce is properly included
		assert arr.length == (NonceSizeBytes + offset);		
		assert arr != null;
		//inritialize prg with nonce and original key
		byte[] new_key = new byte[NonceSizeBytes + KeySizeBytes];
		
		System.arraycopy(this.seed,0,new_key,0,KeySizeBytes);
		System.arraycopy(arr,offset,new_key,KeySizeBytes,NonceSizeBytes);
		
		//renew PRG
		this.prg = new PRGen(new_key);
		
		
	}

	public void setNonce(byte[] nonce) {
		// Reset to initial state, and set a new nonce
		// It is an error to call setNonce with the same nonce
		//    more than once on a single StreamCipher object.
		// StreamCipher does not check for nonce uniqueness;
		//    that is the responsibility of the caller.

		assert nonce.length == NonceSizeBytes;
		assert nonce != null;
		setNonce(nonce,0);
		
	}

	public byte cryptByte(byte in) {
		// Encrypt/decrypt the next byte in the stream
		//generate the prk byte
		byte[] gen_key = new byte[1];
		this.prg.nextBytes(gen_key);
		//System.out.print("\nencryption byte is \n");
		//System.out.print(gen_key[0]);
		//System.out.print("\nbyte for encryption is \n");
		//System.out.print(in);
		//xor with input and return
		in = (byte)(gen_key[0] ^ in);
		//System.out.print("\nResulting xor is " + in);	
		return in;   // IMPLEMENT THIS
	}

	public void cryptBytes(byte[] inBuf, int inOffset, 
			byte[] outBuf, int outOffset, 
			int numBytes) {
		// Encrypt/decrypt the next <numBytes> bytes in the stream
		// Take input bytes from inBuf[inOffset] thru inBuf[inOffset+numBytes-1]
		// Put output bytes at outBuf[outOffset] thru outBuf[outOffset+numBytes-1];

		// IMPLEMENT THIS
		int i = 0;
		for(i = 0;i<numBytes;i++){
			outBuf[i + outOffset] = cryptByte(inBuf[i + inOffset]);
		}
	}
	
	//public static void main(String[] args){

		//Testing Stream Cipher by encrypting and decrypting the same message with two different nonces, which should yield different encryptions

	//	byte[] message = new byte[32];
	//	byte[] key = new byte[32];
	//	byte[] ciph = new byte[32];
	//	int i;
	//	for(i = 0; i < 32;i++){
	//		message[i] = (byte)(i + 2);
	//		key[i] = (byte)i;
	//	}
	//	byte[] nonce1 = new byte[8];
	//	byte[] nonce2 = new byte[8];

	//	for(i = 0; i < 8; i++){
	//		nonce1[i] = (byte)i;
	//		nonce2[i] = (byte)(8 - i);
	//	}
		
	//	StreamCipher streamciph = new StreamCipher(key);
	//	streamciph.setNonce(nonce1);
	//	streamciph.cryptBytes(message,0,ciph,0,32);
	//	System.out.print("\nNonce 1 and 2 Plain Text Message\n");
	//	System.out.print(Arrays.toString(message));
	//	System.out.print("\nNonce 1 Ciph Message\n");
	//	System.out.print(Arrays.toString(ciph));
	//	byte[] deciph = new byte[32];
	//	streamciph.setNonce(nonce1);
	//	streamciph.cryptBytes(ciph,0,deciph,0,32);
	//	System.out.print("\nNonce 1 Deciph Message\n");
	//	System.out.print(Arrays.toString(deciph));
	//	streamciph.setNonce(nonce2);
	//	byte[] ciph2 = new byte[32];
	//	streamciph.cryptBytes(message,0,ciph2,0,32);
	//	byte[] deciph2 = new byte[32];
	//	streamciph.setNonce(nonce2);
	//	streamciph.cryptBytes(deciph2,0,ciph2,0,32);
	//	System.out.print("\nNonce 2 Ciph Message\n");
	//	System.out.print(Arrays.toString(ciph2));
	//	System.out.print("\nNonce 2 Deciph Message \n");
	//	System.out.print(Arrays.toString(deciph2));

	//	}
}	

