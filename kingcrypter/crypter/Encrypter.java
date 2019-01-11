//This class implements functionality for encrypting files.

package kingcrypter.crypter;

import java.io.*;
import java.util.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.security.*;
import java.security.spec.*;

/*
Process:
1. Open file, get its contents <plainInput> and hash it <hash64>
2. Generate RSA keypair <rsaPriv>,<rsaPub>
3. Get current system time (This will be used as AES Initialization Vector) <encTime>
4. Ask user to enter a password <passwd>,<passwdConfirm>
5. Encrypt file with (AES/CBC, passwd, encTime) <cipherText64>
6. Encrypt EncTime with Pub <encTimeRsa64>
7. Write the first output file as: encTimeRsa64;cipherText64;hash64; and the other output file as <filename>_key with the base64-encoded Priv
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
	
	//RSA KeyPair:
	private KeyPair keyPair=null;
	
	//Constructor, takes the input file's name:
	public Encrypter(String inFileName) throws IOException,NoSuchAlgorithmException {
		//Open file:
		File inFile=new File(inFileName);
		//Read file contents:
		FileInputStream inStream=new FileInputStream(inFile);
		this.plainInput=new byte[(int)inFile.length()];
		inStream.read(plainInput);
		//Hash the file:
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
		//Generate RSA keypair:
		KeyPairGenerator kpg=KeyPairGenerator.getInstance("RSA");
		kpg.initialize(rsaKeyLength);
		this.keyPair=kpg.generateKeyPair();
	}
}
