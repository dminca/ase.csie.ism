import java.io.FileInputStream;
import java.security.Key;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.X509Certificate;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import sun.misc.BASE64Decoder;
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
//                        2.4 encrypt secret with receivers public key
                        byte[] byteEncryptWithPublicKey = 
                                encryptUtil.encryptData(senderSecretKey,
                                        pubKeyReceiver, "RSA/ECB/PKCS1Padding");
                        String strSentByteEncryptWithPublicKey = 
                                new BASE64Encoder().encode(byteEncryptWithPublicKey);
                        
//                        3. create message digest of data to be transmitted
                        md.update(byteDataToTransmit);
                        byte byteMofDataToTransmit[] = md.digest();
                        String strMDofDataToTransmit = new String();
                        for(int i=0; i < byteMofDataToTransmit.length; i++)
                        {
                            strMDofDataToTransmit += 
                                    Integer.toHexString((int)byteMDofDataToTransmit[i] & 0xFF);
                        }
//                        3.1. Message to be signed - encrypted secret key + MAC of data to be transmitted
                        String strMsgToSign = strSentByteEncryptWithPublicKey + "|"
                                + strMDofDataToTransmit;
//                        4. sign the message
//                        4.1 get the private key from the keystore
                        char[] keypassword = "test1234".toCharArray();
                        Key mykey = ks.getKey("sender", keypassword);
                        PrivateKey myPrivateKey = (PrivateKey)mykey;
                        
//                        4.2 sign the message
                        Signature mySign = Signature.getInstance("MD5withRSA");
                        mySign.initSign(myPrivateKey);
                        mySign.update(strMsgToSign.getBytes());
                        byte[] byteSignedData = mySign.sign();
                        
//                        5. validate the signature
//                        5.1 extract the sender's public key
                        X509Certificate senderCert;
                        senderCert = (X509Certificate)ks.getCertificate("sender");
                        PublicKey pubKeySender = senderCert.getPublicKey();

//                        5.2 verify the signature
                        Signature myVerifySign = Signature.getInstance("MD5withRSA");
                        myVerifySign.initVerify(pubKeySender);
                        myVerifySign.update(strMsgToSign.getBytes());
                        boolean verifySign = myVerifySign.verify(byteSignedData);
                        if(verifySign == false )
                        {
                            System.out.println("Error in signature verification");
                        }
                        else
                            System.out.println("Signature successfully verified");
                        
//                        6. decrypt message with the receiver's private key
                        char[] recvpassword = "test1234".toCharArray();
                        Key recvkey = ks.getKey("recev", recvpassword);
                        PrivateKey recvPrivateKey = (PrivateKey)recvkey;
                        
//                        6.1 parse the message digest and the encrypted symmetric key
                        String strRecvSignedData = new String(byteSignedData);
                        String[] strRecvSignedDataArray = new String[10];
                        strRecvSignedDataArray = strMsgToSign.split("|");
                        int position = strMsgToSign.indexOf("|");
                        String strEncryptWithPublicKey = strMsgToSign.substring(0,position);
                        String strHashOfData = strMsgToSign.substring(position+1);
                        
//                        6.2 decrypt to get the symmetric key
                        byte[] byteStrEncryptWithPublicKey = 
                                new BASE64Decoder().decodeBuffer(strEncryptWithPublicKey);
                        byte[] byteDecryptWithPrivateKey = 
                                encryptUtil.decryptData(byteEncryptWithPublicKey,
                                        recvPrivateKey, "RSA/ECB/PKCS1Padding");
                        
//                        7. decrypt data using the symmetric key
                        SecretKeySpec secretKeySpecDecrypted = 
                                new SecretKeySpec(byteDecryptWithPrivateKey, "AES");
                        byte[] byteDecryptText = encryptUtil.decryptData(byteCipherText,
                                secretKeySpecDecrypted, "AES");
                        String strDecryptedText = new String(byteDecryptText);
                        System.out.println("Decrypted data is: "+ strDecryptedText);
                        
//                        8. compute message digest of data + signed message
                        MessageDigest recvmd = MessageDigest.getInstance("MD5");
                        recvmd.update(byteDecryptText);
                        byte byteHashOfRecvSignedData[] = recvmd.digest();
                        String strHashOfRecvSignedData = new String();
                        for(int i=0; i < byteHashOfRecvSignedData.length; i++)
                        {
                            strHashOfRecvSignedData += 
                                    Integer.toHexString((int)byteHashOfRecvSignedData[i] & 0xFF);
                        }
                        if(!strHashOfRecvSignedData.equals(strHashOfData))
                            System.out.println("Message has been tampered!");
                        
		}
		catch (Exception e) {
			// TODO: handle exception
                        System.out.println("Exception caught: " + e);
                        e.printStackTrace();
		}
	}
}
