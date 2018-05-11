
public class AuthDecryptor implements Proj1Constants {
	// This class is used to decrypt and authenticate a sequence of values that were encrypted 
	//     by an AuthEncryptor.
	
	private byte[] enckey;
	private byte[] mackey;
	private StreamCipher streamciph;
	private PRF MAC;
	
	
	public AuthDecryptor(byte[] key) {
		assert key.length == KeySizeBytes;
		enckey = new byte[KeySizeBytes];
		mackey = new byte[KeySizeBytes];

                PRGen prg = new PRGen(key);
		prg.nextBytes(enckey);
		prg.nextBytes(mackey);
		//prf as an hmac
		this.MAC = new PRF(mackey);
		// IMPLEMENT THIS
	}

	public byte[] decrypt(byte[] in, byte[] nonce, boolean nonceIncluded) {
		// Decrypt and authenticate the contents of <in>.  The value passed in will normally
		//    have been created by calling encrypt() with the same nonce in an AuthEncryptor 
		//    that was initialized with the same key as this AuthDecryptor.
		// If <nonceIncluded> is true, then the nonce has been included in <in>, and
		//    the value passed in as <nonce> will be disregarded.
		// If <nonceIncluded> is false, then the value of <nonce> will be used.
		// If the integrity of <in> cannot be verified, then this method returns null.   Otherwise it returns 
		//    a newly allocated byte-array containing the plaintext value that was originally 
		//    passed to encrypt().
		assert in != null;
		assert in.length != 0;
		//initialize streamciph with encryption key
		streamciph = new StreamCipher(enckey);
		//streamciph.setNonce(nonce);
		//in_msg_pos is where the end of the cipher msg is.
		int in_msg_pos = in.length - KeySizeBytes;
		if(nonceIncluded) in_msg_pos -= NonceSizeBytes;
		//compute the mac based on the given key
		byte[] comp_MAC = new byte[KeySizeBytes];
		comp_MAC = this.MAC.eval(in,0,in_msg_pos);
		byte[] der_MAC = new byte[KeySizeBytes];
		if(nonceIncluded){
			System.arraycopy(in,(in.length - KeySizeBytes),der_MAC,0,KeySizeBytes);
			//check if mac found in in is the same as the computed mac
			if(!(new String(comp_MAC).equals(new String(der_MAC)))){
				System.out.print("Tampered MAC");
				return null;
			}
			byte[] new_nonce = new byte[NonceSizeBytes];
			System.arraycopy(in,in_msg_pos,new_nonce,0,NonceSizeBytes);
			if(!(new String(new_nonce).equals(new String(nonce)))){
				System.out.print("Error: provided nonce, does not equal encrypt nonce");
				return null;
			}
			byte[] ptext = new byte[in_msg_pos];
			streamciph.setNonce(new_nonce);
			//decrypt the msg cipher text
			streamciph.cryptBytes(in,0,ptext,0,in_msg_pos);
			return ptext;
		}else{
			System.arraycopy(in,(in.length - KeySizeBytes), der_MAC, 0, KeySizeBytes);
			if(!(new String(comp_MAC).equals(new String(der_MAC)))){
				System.out.print("Tampered MAC");
				return null;
			}
			streamciph.setNonce(nonce);
			byte[] ptext = new byte[in_msg_pos];
			streamciph.cryptBytes(in,0,ptext,0,in_msg_pos);
			return ptext;  // IMPLEMENT THIS
			}
	}

	//public static void main(String[] argv){
	//byte[] key = new byte[KeySizeBytes];
        //for(int i = 0; i < KeySizeBytes; i++) key[i] = (byte)i;

        //byte[] message = new byte[5];
        //for(int i = 0; i < 5; i++) message[i] = (byte)i;


        //byte[] nonce = new byte[NonceSizeBytes];
        //for(int i = 0; i < 8; i++){
      //          nonce[i] = (byte)(i+5);
    //    }

  //      AuthEncryptor ae = new AuthEncryptor(key);
//        byte[] enc = ae.encrypt(message,nonce,true);

    //    System.out.print("\n Encrypted Message is 1 2 3 4 5\n");
  //      AuthDecryptor ad = new AuthDecryptor(key);
//	byte[] d_msg = ad.decrypt(enc,nonce,true);
  //      for(int i = 0; i < d_msg.length; i++){
//		System.out.print(d_msg[i]);

 //       }
//	}
}

