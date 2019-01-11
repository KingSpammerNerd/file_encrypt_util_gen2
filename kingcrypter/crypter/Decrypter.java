//This class implements functionality for decrypting files encrypted by kingcrypter.

package kingcrypter.crypter;

/*
Process:
1. Read the first file and parse its contents <EncTimeRSA64>,<CipherText64>,<Hash64>
2. Load the private key file and decrypt EncTimeRSA64
Proceed as for encryption, but in reverse (duh)
*/

public class Decrypter {
	//MessageDigest object, for SHA-256 hashing:
	MessageDigest hash256=null;
	
	//Input file bytes:
	private byte[] encInput=null;
	
	//Constructor:
	
}
