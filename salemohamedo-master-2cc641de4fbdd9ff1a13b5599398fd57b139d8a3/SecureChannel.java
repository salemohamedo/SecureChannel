
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Arrays;

public class SecureChannel extends InsecureChannel {
	// This is just like an InsecureChannel, except that it provides 
	//    authenticated encryption for the messages that pass
	//    over the channel.   It also guarantees that messages are delivered 
	//    on the receiving end in the same order they were sent (returning
	//    null otherwise).  Also, when the channel is first set up,
	//    the client authenticates the server's identity, and the necessary
	//    steps are taken to detect any man-in-the-middle (and to close the
	//    connection if a MITM is detected).
	//
	// The code provided here is not secure --- all it does is pass through
	//    calls to the underlying InsecureChannel.
	protected PRGen prgen;
	protected PRGen nonce_prg;
	protected byte[] master_key;
	protected AuthEncryptor encrypt;
	protected AuthDecryptor decrypt;
	protected byte[] pre_master_secret;
	protected byte[] history;
	protected char[] master_key_chars = {'m','a','s','t','e','r',' ','k','e','y'};
	protected String master_key_string = new String(master_key_chars);
	protected byte[] master_key_str_bytes = master_key_string.getBytes();
	protected char[] server_finished_chars = {'s','e','r','v','e','r',' ','f','i','n','i','s','h','e','d'};
	protected String server_finished_str = new String(server_finished_chars);
	protected byte[] server_finished = server_finished_str.getBytes();
        protected char[] client_finished_chars = {'c','l','i','e','n','t',' ','f','i','n','i','s','h','e','d'};
        protected String client_finished_str = new String(client_finished_chars);
        protected byte[] client_finished = client_finished_str.getBytes();

	public SecureChannel(InputStream inStr, OutputStream outStr, 
			PRGen rand, boolean iAmServer,
			RSAKey serverKey) throws IOException {
		// if iAmServer==false, then serverKey is the server's *public* key
		// if iAmServer==true, then serverKey is the server's *private* key
		//using DH for premasterkey and initial key exchange;
		super(inStr, outStr);
		this.prgen = rand; 

		KeyExchange ke = new KeyExchange(rand);
	
		byte[] pre_master = ke.prepareOutMessage();
		if(iAmServer){
			byte[] server_random = new byte[32];
			prgen.nextBytes(server_random);
			super.sendMessage(server_random);
			byte[] client_random = super.receiveMessage();
			//server signs their contribution to the pre_master_secret
			byte[] sign = serverKey.sign(pre_master,this.prgen);
			super.sendMessage(pre_master);
			super.sendMessage(sign);
			//use the pre_master_secret, client and server randoms to produce the master_key
			this.pre_master_secret = ke.processInMessage(super.receiveMessage());
                         PRF find_master_key = new PRF(this.pre_master_secret);
                         byte[] master_key_input = new byte[32 + 32 + master_key_str_bytes.length];
                         System.arraycopy(client_random,0,master_key_input,0,32);
                         System.arraycopy(server_random,0,master_key_input,32,32);
                         System.arraycopy(master_key_str_bytes,0,master_key_input,64,master_key_str_bytes.length);
                         this.master_key = find_master_key.eval(master_key_input);
			
			//send the client prf(seeded with masterkey)["server finished" || hash(history)
			int history_len = master_key_input.length + this.pre_master_secret.length + sign.length;
                        history = new byte[history_len];
                        System.arraycopy(master_key_input,0,history,0,master_key_input.length);
                        System.arraycopy(this.pre_master_secret,0,history,master_key_input.length,pre_master_secret.length);
                        System.arraycopy(sign,0,history,master_key_input.length + pre_master_secret.length,sign.length);
                        byte[] history_hash = Proj2Util.hash(history);
                        byte[] final_message = new byte[history_hash.length + server_finished.length];
                        System.arraycopy(server_finished,0,final_message,0,server_finished.length);
                        System.arraycopy(history_hash,0,final_message,server_finished.length,history_hash.length);
                        PRF master_key_prf = new PRF(this.master_key);
                        super.sendMessage(master_key_prf.eval(final_message));
			//check that the clients response is the same, and thus that the two of you have the same master key
                        byte[] client_final_message = super.receiveMessage();
                        PRF confirm = new PRF(this.master_key);
                        byte[] final_message_client = new byte[client_finished.length + history_hash.length];
                        System.arraycopy(client_finished,0,final_message_client,0,client_finished.length);
                        System.arraycopy(history_hash,0,final_message_client,client_finished.length,history_hash.length);
                        if(!(Arrays.equals(client_final_message,confirm.eval(final_message_client)))) super.close();

			
		}
		else{	//client
			byte[] client_random = new byte[32];
			this.prgen.nextBytes(client_random);
			super.sendMessage(client_random);
			byte[] server_random = super.receiveMessage();
		
			//client sends their contribution to the pre_master_secret
			super.sendMessage(pre_master);
			
			byte[] in_master_key = super.receiveMessage();
			byte[] server_sign = super.receiveMessage();
			//verify signature of server otherwise close();	
			if(serverKey.verifySignature(in_master_key,server_sign)!= true)	super.close();
			//generate pre_master_secret which is used to generate master_key
			this.pre_master_secret = ke.processInMessage(in_master_key);
			PRF find_master_key = new PRF(this.pre_master_secret);
			byte[] master_key_input = new byte[32 + 32 + master_key_str_bytes.length];
			System.arraycopy(client_random,0,master_key_input,0,32);
			System.arraycopy(server_random,0,master_key_input,32,32);
			System.arraycopy(master_key_str_bytes,0,master_key_input,64,master_key_str_bytes.length);
			this.master_key = find_master_key.eval(master_key_input);
			//send the server prf(seeded with masterkey)["client finished" || hash(history)]
			int history_len = master_key_input.length + this.pre_master_secret.length + server_sign.length;
			history = new byte[history_len];
			System.arraycopy(master_key_input,0,history,0,master_key_input.length);
			System.arraycopy(this.pre_master_secret,0,history,master_key_input.length,pre_master_secret.length);
			System.arraycopy(server_sign,0,history,master_key_input.length + pre_master_secret.length,server_sign.length);
			byte[] history_hash = Proj2Util.hash(history);
			byte[] final_message = new byte[history_hash.length + client_finished.length];
			System.arraycopy(client_finished,0,final_message,0,client_finished.length);
			System.arraycopy(history_hash,0,final_message,client_finished.length,history_hash.length);
			PRF master_key_prf = new PRF(this.master_key);
			super.sendMessage(master_key_prf.eval(final_message));
			//check that the server response is what you expected, and thus that the two of you have the same master key
			byte[] server_final_message = super.receiveMessage();
			PRF confirm = new PRF(this.master_key);
			byte[] final_message_server = new byte[server_finished.length + history_hash.length];
			System.arraycopy(server_finished,0,final_message_server,0,server_finished.length);
			System.arraycopy(history_hash,0,final_message_server,server_finished.length,history_hash.length);
			if(!(Arrays.equals(server_final_message,confirm.eval(final_message_server)))) super.close();
			
		}
		this.nonce_prg = new PRGen(master_key);
		this.encrypt = new AuthEncryptor(master_key);
		this.decrypt = new AuthDecryptor(master_key);
		// IMPLEMENT THIS
	}

	public void sendMessage(byte[] message) throws IOException {
		byte[] nonce = new byte[8];
		//encrypt message with authencryptor, and add a nonce each time to defend against replay attacks
		this.nonce_prg.nextBytes(nonce);
		//System.out.print("\n Nonce size: " + nonce.length + "message size: " + message.length + "\n");
		//AuthEncryptor encrypt = new AuthEncryptor(addsomething);
		//System.out.print(Arrays.toString(nonce));
		byte[] cipher = encrypt.encrypt(message,nonce,true);
		//PRF hash = new PRF(this.pre_master_secret);
		//byte[] hash_history = new byte[PRFOutputSizeBytes];
		//hash_history = hash.eval(history);
		//byte[] new_message = new byte[cipher.length + history.length];
		//System.arraycopy(cipher,0,new_message,0,cipher.length);
		//System.arraycopy(history,0,new_message,cipher.length,history.length);
	
		
		super.sendMessage(cipher);    // IMPLEMENT THIS
	}

	public byte[] receiveMessage() throws IOException {
		byte[] new_message = super.receiveMessage();
		byte[] nonce = new byte[8];
		this.nonce_prg.nextBytes(nonce);
		//byte[] hash_history = new byte[new_message.length - PRFOutputSizeBytes];
		//System.arraycopy(new_message,new_message.length - PRFOutputSizeBytes,hash_history,PRFOutputSizeBytes);
		//byte[] exp_hash_history = new byte[PRFOutputSizeBytes];
		//PRF prf2 = new PRF(this.pre_master_secret);
		//exp_hash_history = prf2.eval(received_history);

		//if(!(Arrays.equals(exp_hash_history,hash_history))) close();
		//check that the nonce in the other party's message is fresh and also what you expected to see if reordering occured
		byte[] new_message_nonce = new byte[8];
		System.arraycopy(new_message,new_message.length - 8, new_message_nonce,0, 8);
		if(!(Arrays.equals(nonce,new_message_nonce))) return null;
		//byte[] ptext = new byte[new_message.length - PRFOutputSizeByte];
		//System.arraycopy(new_message,0,ptext,0,new_message.length - PRFOutputSizeBytes);
		//AuthDecryptor decrypt = new AuthDecryptor(this.pre_master_secret);
		//decrypt the message
		return decrypt.decrypt(new_message,nonce,true);
	}
}
