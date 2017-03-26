import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.cert.X509Certificate;

import javax.crypto.SecretKey;
import sun.misc.BASE64Encoder;

public class DigitalSignature {

	public static void main(String[] args) {
		// TODO Auto-generated method stub
		//1.creates the symmetric key to encrypt the message
		SymmetricEncrypt encryptUtil = new SymmetricEncrypt();
		String strDataToEncrypt = "Hello World";
		byte[] byteDataToTransmit = strDataToEncrypt.getBytes();
		//generating a secret key for the symmetric encryption
		SecretKey senderSecretKey = SymmetricEncrypt.getSecret();
		
		byte[] byteCipherText = encryptUtil.encryptData
				(byteDataToTransmit, senderSecretKey, "AES");	
		String strCipherText = new BASE64Encoder().
				encode(byteCipherText);
		//2.Encrypt the Symmetric key using the receiver's public key
		try
		{
			//2.1 opening the keystore
			KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
			char[] password = "test1234".toCharArray();
			FileInputStream fis = new FileInputStream("testkeystore.ks");
			ks.load(fis, password);
			fis.close();
			//2.2 creating and X509 certificate for the receiver
			X509Certificate recvcert;
			MessageDigest md = MessageDigest.getInstance("MD5");
			recvcert = (X509Certificate)ks.getCertificate("recev");
			//2.3 get out the public key from the certificate
			PublicKey pubKeyReceiver = recvcert.getPublicKey();
		}
		catch (Exception e) {
			// TODO: handle exception
		}
		
		
	}

}
