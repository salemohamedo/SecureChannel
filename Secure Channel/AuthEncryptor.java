
public class AuthEncryptor implements Proj1Constants {
	// This class is used to compute the authenticated encryption of values.  
	//     Authenticated encryption protects the confidentiality of a value, so that the only 
	//     way to recover the initial value is to do authenticated decryption of the value using the 
	//     same key and nonce that were used to encrypt it.   At the same time, authenticated encryption
	//     protects the integrity of a value, so that a party decrypting the value using
	//     the same key and nonce (that were used to decrypt it) can verify that nobody has tampered with the
	//     value since it was encrypted.
	
	private PRF MAC;
	//private StreamCipher streamciph;
	private byte[] input_key;
	private byte[] enckey;
	private byte[] mackey;
	private StreamCipher streamciph;
	
	public AuthEncryptor(byte[] key) {
		assert key.length == KeySizeBytes;
		this.input_key = key;
		//for encrypting plain text/nonce
		enckey = new byte[KeySizeBytes];
		//for encrypting resulting ciphertext
		mackey = new byte[KeySizeBytes];
		
		//system.arraycopy(key,0,key1,0,24);
		//system.arraycopy(key,24,key2,0,8);

		//streamciph = new StreamCipher(enc);
		PRGen prg = new PRGen(key);
		prg.nextBytes(enckey);
		prg.nextBytes(mackey);
		//prf is an hmac
		this.MAC = new PRF(mackey);
		// IMPLEMENT THIS
	}

	public byte[] encrypt(byte[] in, byte[] nonce, boolean includeNonce) {
		// Encrypts the contents of <in> so that its confidentiality and 
		//    integrity are protected against would-be attackers who do 
		//    not know the key that was used to initialize this AuthEncryptor.
		// Callers are forbidden to pass in the same nonce more than once;
		//    but this code will not check for violations of this rule.
		// The nonce will be included as part of the output iff <includeNonce>
		//    is true.  The nonce should be in plaintext if it is included.
		//
		// This returns a newly allocated byte[] containing the authenticated
		//    encryption of the input.
		//setup streamciph to encrypt plaintext
		assert in != null;
		assert in.length != 0;
		streamciph = new StreamCipher(enckey);
		streamciph.setNonce(nonce);
		
		byte[] ciphermsg;
		ciphermsg = new byte[in.length];
		streamciph.cryptBytes(in,0,ciphermsg,0,in.length);
		//hmac on ciphertext
		byte[] MAC_output = this.MAC.eval(ciphermsg);
		
		byte [] output;
		int outputlen = KeySizeBytes + in.length;
		if(includeNonce){
			outputlen += NonceSizeBytes;
		}
		//output either includes cipher + MAC + nonce or no nonce
		output = new byte[outputlen];

		if(includeNonce){
			System.arraycopy(ciphermsg,0,output,0,in.length);
			System.arraycopy(nonce,0,output,in.length,NonceSizeBytes);
			System.arraycopy(MAC_output,0,output,(in.length + NonceSizeBytes),KeySizeBytes);
		}
		else { 
			System.arraycopy(ciphermsg,0,output,0,in.length);
			System.arraycopy(MAC_output,0,output,in.length,KeySizeBytes);
		}

		return output;

	}

//	public static void main(String[] argv){
		
//	byte[] key = new byte[KeySizeBytes];
//	for(int i = 0; i < KeySizeBytes; i++) key[i] = (byte)i;

//	byte[] message = new byte[5];
//	for(int i = 0; i < 5; i++) message[i] = (byte)i;
	

//	byte[] nonce = new byte[NonceSizeBytes];
//	for(int i = 0; i < 8; i++){
//		nonce[i] = (byte)(i+5);	
//	}

//	AuthEncryptor ae = new AuthEncryptor(key);
//	byte[] enc = ae.encrypt(message,nonce,true);
	
//	System.out.print("\n Encrypted Message Should be 45 bytes long\n");
//	for(int i = 0; i<enc.length;i++){
//		System.out.print(enc[i]);
//		System.out.print("\n");
//	}
//	System.out.print("en length is" + enc.length);

//	}
}
