//This class implements functionality for encrypting files.

package kingcrypter.crypter;

/*
Process:
1. Open file, get its contents <PlainText> and hash it <Hash64>
2. Generate RSA keypair <Priv>,<Pub>
3. Get current system time (This will be used as AES Initialization Vector) <EncTime>
4. Ask user to enter a password <Passwd>,<PasswdConfirm>
5. Encrypt file with (AES/CBC, Passwd, EncTime) <CipherText64>
6. Encrypt EncTime with Pub <EncTimeRSA64>
7. Write the first output file as: EncTimeRSA64;CipherText64;Hash64; and the other output file as <filename>_key with the base64-encoded Priv
*/

public class Encrypter {
	
}
