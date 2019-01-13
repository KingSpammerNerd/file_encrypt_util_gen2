package kingcrypter.crypter;

/*This class is used to store the output of the encryption process as follows:
1. Base64-encoded encrypted IV
2. Base64-encoded ciphertext
3. Base64-encoded SHA-256 hash of the plaintext
4. Base64-encoded RSA private key
*/

public class EncryptedOutput {
	private String encIvRsa64=null, cipherText64=null, hash64=null, rsaPriv64=null;
	private int rsaKeyLength=0;
	
	//The decrypter class uses a similar constructor:
	public EncryptedOutput(String encIvRsa64, String cipherText64, String hash64, String rsaPriv64, int rsaKeyLength) {
		this.encIvRsa64=encIvRsa64;
		this.cipherText64=cipherText64;
		this.hash64=hash64;
		this.rsaPriv64=rsaPriv64;
		this.rsaKeyLength=rsaKeyLength;
	}
	
	public String getEncIV() {
		return this.encIvRsa64;
	}
	
	public String getCipherText() {
		return this.cipherText64;
	}
	
	public String getHash() {
		return this.hash64;
	}
	
	public String getPrivateKey() {
		return this.rsaPriv64;
	}
	
	public int getKeyLength() {
		return this.rsaKeyLength;
	}
}
