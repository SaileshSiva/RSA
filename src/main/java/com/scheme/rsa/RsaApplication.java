package com.scheme.rsa;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;

@SpringBootApplication
public class RsaApplication {

	public static void main(String[] args) throws IOException, CertificateException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, InvalidKeySpecException, BadPaddingException, InvalidKeyException {
		RSA rsa = new RSA();
		String publicEncryptionFile = "/home/sailesh/Documents/rsa/src/main/resources/keys/encryption/certificate.crt";
		String publicSignFile = "/home/sailesh/Documents/rsa/src/main/resources/keys/signature/certificate.crt";

		FileInputStream inputStream = new FileInputStream(publicEncryptionFile);
		CertificateFactory factory = CertificateFactory.getInstance("X.509");
		Certificate certificate = factory.generateCertificate(inputStream);

		RSAPublicKey publicEncKey = rsa.getPublicKeyFromCertificate(publicEncryptionFile);
		System.out.println(publicEncKey);
		String message = "hi da Kirishi";
		String encryptedMessage = rsa.encrypt(certificate, message);
		System.out.println(encryptedMessage);
		System.out.println(rsa.decrypt(encryptedMessage));

		FileInputStream inputStream2 = new FileInputStream(publicSignFile);
		CertificateFactory factory2 = CertificateFactory.getInstance("X.509");
		Certificate certificate2 = factory2.generateCertificate(inputStream2);

		String signature = rsa.signMessage(message);
		if (rsa.varifySignature(signature,message, certificate2)){
			System.out.println("Signature Varified");
		}else {
			System.out.println("Violated");
		}

		//SpringApplication.run(RsaApplication.class, args);
		//System.out.println("Springboot Application Started Successfully!");

		////////////////////////////
		//String sample = "Hello my dear friend\naufsdafjnsadfjknaslkfnassfubwqiuofnwauncascsa\nasfasnfauisbfnaishb\nasfansfihasnfcakjefniajs fasjkdjk322jnjn\n 123e412\n";
//		String sample = "Hi da Kirishi";
//		byte[] sampleArray = sample.getBytes(StandardCharsets.UTF_8);
//		//System.out.println(Arrays.toString(sampleArray));
//
//		Path privateEncryptionKeyFile = Paths.get("../rsa/src/main/resources/keys/encryption/private.der");
//
//		byte[] privateKeyByteArray = Files.readAllBytes(privateEncryptionKeyFile);
//
//		PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKeyByteArray);
//		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
//		RSAPrivateKey privateKey = (RSAPrivateKey) keyFactory.generatePrivate(keySpec);
//
//		FileInputStream fileInputStream = new FileInputStream("/home/sailesh/Documents/rsa/src/main/resources/keys/encryption/certificate.crt");
//		CertificateFactory factory = CertificateFactory.getInstance("X.509");
//		Certificate cer = factory.generateCertificate(fileInputStream);
//
//		RSAPublicKey publicKey = (RSAPublicKey) cer.getPublicKey();
////
////		String s = bytesToString(sampleArray);
////		System.out.println(s);
//
////		Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
////		cipher.init(Cipher.ENCRYPT_MODE, publicKey);
////		byte[] crypted = cipher.doFinal(sample.getBytes());
////
////		System.out.println(Arrays.toString(crypted));
////
////		Cipher cipher2 = Cipher.getInstance("RSA/ECB/PKCS1Padding");
////		cipher2.init(Cipher.DECRYPT_MODE, privateKey);
////		String sssss = new String(cipher2.doFinal(crypted));
////
////		System.out.println(sssss);
//		BigInteger integer = new BigInteger(sampleArray);
//		byte [] try1 = integer.modPow(publicKey.getPublicExponent(), publicKey.getModulus()).toByteArray();
//		String cipherText = Base64.getEncoder().encodeToString(try1);
//		System.out.println(cipherText);
//		byte[] reCipherBytes = Base64.getDecoder().decode(cipherText);
//		byte [] try2 = (new BigInteger(reCipherBytes)).modPow(privateKey.getPrivateExponent(), privateKey.getModulus()).toByteArray();
//		String retry = new String(try2);
//		System.out.println(retry);
//		//System.out.println("Encrypted :" + cipherText);
//		//System.out.println("Encrypted 2 :" + Arrays.toString(reCipherBytes));
//		//System.out.println(retry);
//		if (Arrays.equals(try1, reCipherBytes)){
//			System.out.println("Correct!!");
//		}else{
//			System.out.println("Wrong!!");
//		}


//		Path privateSignKeyFile = Paths.get("../electionCommission/src/main/resources/keys/signature/private.der");
//		byte[] privateKeyByteArray2 = Files.readAllBytes(privateSignKeyFile);
//
//		PKCS8EncodedKeySpec keySpec2 = new PKCS8EncodedKeySpec(privateKeyByteArray2);
//		KeyFactory keyFactory2 = KeyFactory.getInstance("RSA");
//		RSAPrivateKey signingKey = (RSAPrivateKey) keyFactory2.generatePrivate(keySpec2);
//
//		String hashedMessage = Hashing.sha256().hashString(sample, StandardCharsets.UTF_8).toString();;
//
//		byte[] sign = (new BigInteger(hashedMessage.getBytes(StandardCharsets.UTF_8)))
//				.modPow(signingKey.getPrivateExponent(), signingKey.getModulus()).toByteArray();
//		String signstring = Base64.getEncoder().encodeToString(sign);;
//
//
//
//		System.out.println(signstring);
//
//		FileInputStream fileInputStream2 = new FileInputStream("/home/sailesh/Documents/crypto/cloned/Election_Commission/electionCommission/src/main/resources/keys/signature/certificate.crt");
//		CertificateFactory factory2 = CertificateFactory.getInstance("X.509");
//		Certificate cer2 = factory2.generateCertificate(fileInputStream2);
//
//		RSAPublicKey publicsignKey = (RSAPublicKey) cer2.getPublicKey();
//
//		byte[] seco = Base64.getDecoder().decode(signstring);
//		byte[] seco2 = (new BigInteger(seco)).modPow(publicsignKey.getPublicExponent(), publicsignKey.getModulus()).toByteArray();
//
//		String varify = new String(seco2);
//		if (varify.equals(hashedMessage)){
//			System.out.println("Integrity");
//		}else {
//			System.out.println("Violated");
//		}

	}

}
