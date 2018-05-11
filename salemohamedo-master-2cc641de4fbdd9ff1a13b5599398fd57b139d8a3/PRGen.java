
import java.util.Random;


public class PRGen extends Random implements Proj1Constants {
	// This implements a pseudorandom generator.  It extends java.util.Random, which provides
	//     a useful set of utility methods that all build on next(.).  See the documentation for
	//     java.util.Random for an explanation of what next(.) is supposed to do.
	// If you're calling a PRGen, you probably want to call methods of the Random superclass.
	//
	// There are two requirements on a pseudorandom generator.  First, it must be pseudorandom,
	//     meaning that there is no (known) way to distinguish its output from that of a
	//     truly random generator, unless you know the key.  Second, it must be deterministic, 
	//     which means that if two programs create generators with the same seed, and then
	//     the two programs make the same sequence of calls to their generators, they should
	//     receive the same return values from all of those calls.
	// Your generator must have an additional property: backtracking resistance.  This means that if an
	//     adversary is able to observe the full state of the generator at some point in time, that
	//     adversary cannot reconstruct any of the output that was produced by previous calls to the
	//     generator.
	private PRF prf;
	private byte[] STATE;

	public PRGen(byte[] seed) {
		super();
		assert seed.length == KeySizeBytes;
		STATE = seed;
		//initialize prf with seed
		prf = new PRF(STATE);
		

		// IMPLEMENT THIS
	}

	protected int next(int bits) {
		// For description of what this is supposed to do, see the documentation for 
		//      java.util.Random, which we are subclassing.
		//ensure that outbits is in the correct range.
		assert 1 <= bits && bits <= 32;
		byte [] out = {23,4,9,12}; // arb init constants
		byte [] restart = {11,6,15,33};
		PRF prf = new PRF(STATE);
		byte [] ran_eval = prf.eval(out);
		int compress_bits = 0;
		//compress the bits
		int i = 0;
		for(i = 0;i < 4; i++){
			compress_bits = (ran_eval[i] & 0xff) + (compress_bits << 8);
		}
		STATE = prf.eval(restart);//refresh the state
		prf = new PRF(STATE);//update for backtracking resistance
		compress_bits = compress_bits >> (32 - bits);
		return compress_bits;   // IMPLEMENT THIS
	}



//	public static void main(String[] argv){

//		byte[] key_test = new byte[KeySizeBytes];
//		byte[] key_test2 = new byte[KeySizeBytes];
//		for(int i = 0;i < KeySizeBytes; i++) {
//			key_test[i] = (byte)i;
//			key_test2[i] = (byte)(32-i);
//		}
//		PRGen prg1 = new PRGen(key_test);
//		PRGen prg2 = new PRGen(key_test);
//		PRGen prg3 = new PRGen(key_test2);

//		int versions = 0;

	//	for(versions = 0; versions < 5; versions++){
	//		System.out.print("\nPRG1 Output Key 1\n");
	//		System.out.print(prg1.next(4));
	//		System.out.print("\nPRG2 Output Key 1\n");
	//		System.out.print(prg2.next(4));
	//		System.out.print("\nPRG3 Output Key 2\n");
	//		System.out.print(prg3.next(7));
	//	}

		//}
}
