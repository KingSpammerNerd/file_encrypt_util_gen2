//This class implements functionality for decrypting files encrypted by kingcrypter.

package kingcrypter.crypter;

/*
Process:
1. Read the first file and parse its contents <EncTimeRSA64>,<CipherText64>,<Hash64>
2. Load the private key file and decrypt EncTimeRSA64
Proceed as for encryption, but in reverse (duh)
*/

import java.security.*;
import java.security.spec.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.util.*;

public class Decrypter {
	//MessageDigest object, for SHA-256 hashing:
	MessageDigest hash256=null;
	
	//IV object:
	private IvParameterSpec encIv=null;
	
	//Input file bytes:
	private byte[] encInput=null;
	//Base64-encoded hash of plaintext:
	private String hash64=null;
	//Output plaintext:
	private byte[] decOutput=null;
	
	//Input RSA Private key:
	private PrivateKey rsaPriv=null;
	//Input RSA key length:
	private int keyLength=0;
	
	//Constructor. Also decrypts the IV:
	public Decrypter(EncryptedOutput input) throws NoSuchAlgorithmException,InvalidKeySpecException,NoSuchPaddingException,BadPaddingException,InvalidKeyException,IllegalBlockSizeException {
		//Get Private key length:
		this.keyLength=input.getKeyLength();
		//Get Private key:
		String rsaPrivEncoded64=input.getPrivateKey();
		byte[] rsaPrivEncoded=Base64.getDecoder().decode(rsaPrivEncoded64.getBytes());
		X509EncodedKeySpec x509Priv=new X509EncodedKeySpec(rsaPrivEncoded);
		KeyFactory pkFac=KeyFactory.getInstance("RSA");
		this.rsaPriv=pkFac.generatePrivate(x509Priv);
		//Get ciphertext and decode it:
		byte[] encInput64=input.getCipherText().getBytes();
		this.encInput=Base64.getDecoder().decode(encInput64);
		//Get base64-encoded SHA-256 hash:
		this.hash64=input.getHash();
		//Get encrypted IV and decode it:
		String encIvRsa64=input.getEncIV();
		byte[] encIvRsa=Base64.getDecoder().decode(encIvRsa64);
		//Decrypt AES IV:
		Cipher dec=Cipher.getInstance("RSA");
		dec.init(Cipher.DECRYPT_MODE, this.rsaPriv);
		byte[] encIvBytes=dec.doFinal(encIvRsa);
		this.encIv=new IvParameterSpec(encIvBytes);
	}
	
	//Perform decryption, given the file's password:
	public void doDecrypt(String password) throws NoSuchAlgorithmException,InvalidKeyException,NoSuchPaddingException,BadPaddingException,InvalidAlgorithmParameterException,IllegalBlockSizeException {
		//Get bytes from password:
		byte[] pass=password.getBytes();
		byte[] passHash=this.hash256.digest(pass);
		//Create AES cipher:
		Cipher dec=Cipher.getInstance("AES");
		dec.init(Cipher.DECRYPT_MODE, new SecretKeySpec(passHash, "AES"), this.encIv);
		//Decrypt data:
		this.decOutput=dec.doFinal(this.encInput);
	}
	
	//Get the plaintext as a byte array:
	public byte[] getOutput() {
		return this.decOutput;
	}
}
