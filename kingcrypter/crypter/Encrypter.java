//This class implements functionality for encrypting raw data.
//CONTINUE FROM LINE 87
package kingcrypter.crypter;

import java.io.*;
import java.util.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.security.*;
import java.security.spec.*;

/*
Process:
1. Read an array of bytes <plainInput> and hash it <hash64>
2. Generate RSA keypair <rsaPriv>,<rsaPub>
3. Get current system time (This will be used as AES Initialization Vector) <encTime>
4. Ask user to enter a password <passwd>
5. Encrypt file with (AES/CBC, passwd, encTime) <cipherText64>
6. Encrypt EncTime with Pub <encTimeRsa64>
7. Write the first output file as: encIvRsa64;cipherText64;hash64; and the other output file as <filename>_key with the base64-encoded Priv
*/

public class Encrypter {
	//MessageDigest object, for SHA-256 hashing:
	MessageDigest hash256=null;
	
	//Input file bytes:
	private byte[] plainInput=null;
	//Input file hash, encoded to base64:
	private String hash64=null;
	
	//System time when beginning and ending the preliminary data entry step:
	private long startTime=0, endTime=0;
	//The hash of their difference is used as the AES Initialization Vector.
	
	//Password used:
	private String passwd=null;
	//IV for AES encryption:
	private IvParameterSpec encIv=null;
	
	//Output encrypted IV bytes, encoded to base64:
	private String encIvRsa64=null;
	//Output ciphertext, encoded to base64:
	private String cipherText64=null;
	
	//RSA KeyPair:
	private KeyPair keyPair=null;
	//RSA key size:
	int rsaKeyLength=0;
	
	//Constructor, takes raw data to be encrypted:
	public Encrypter(byte[] input) throws NoSuchAlgorithmException {
		//Copy bytes:
		this.plainInput=input;
		//Hash the data:
		this.hash256=MessageDigest.getInstance("SHA-256");
		byte[] hash=this.hash256.digest(this.plainInput);
		//Encode hash to base64:
		this.hash64=Base64.getEncoder().encodeToString(hash);
	}
	
	//Generate RSA keypair and get system time:
	public void genRsaKeyPair(int rsaKeyLength) throws RuntimeException,NoSuchAlgorithmException {
		//Check key length:
		if(!(rsaKeyLength==2048 || rsaKeyLength==4096))
			throw new RuntimeException("Invalid key length, use 2048 or 4096!");
		this.rsaKeyLength=rsaKeyLength;
		//Generate RSA keypair:
		KeyPairGenerator kpg=KeyPairGenerator.getInstance("RSA");
		kpg.initialize(rsaKeyLength);
		this.keyPair=kpg.generateKeyPair();
	}
	
	//Create IvParameterSpec for encryption, using the first 16 bytes of hash of endTime-startTime. Called from setPasswd:
	//Also, encrypt the IV in this step.
	private void createIv(long timeDiff) {
		//Convert timeDiff to String:
		String diffStr=String.valueOf(timeDiff);
		//Hash diffStr:
		byte diffStrHash[]=this.hash256.digest(diffStr.getBytes());
		//Store first 16 bytes of diffStrHash as IvParameterSpec:
		this.encIv=new IvParameterSpec(Arrays.copyOf(diffStrHash, 16));
		//Encrypt the IV:
		Cipher enc=Cipher.getInstance("RSA");
		enc.init(this.rsaKeyLength);
		byte[] encIvRsa=enc.doFinal(Cipher.ENCRYPT_MODE, this.keyPair.getPublic());
		//CONTINUE FROM HERE
	}
	
	//Get and store password. Confirmation of password is to be done by calling method:
	public void setPasswd(String passwd) {
		this.passwd=new String(passwd);
		this.endTime=System.currentTimeMillis();
		this.createIv(this.endTime-this.startTime);
	}
}
