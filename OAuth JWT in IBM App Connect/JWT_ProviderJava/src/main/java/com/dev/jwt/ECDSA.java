package com.dev.jwt;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.util.Date;

import com.ibm.security.x509.AlgorithmId;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.ECKey.Builder;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.shaded.gson.JsonArray;
import com.nimbusds.jose.shaded.gson.JsonObject;
import com.nimbusds.jose.shaded.gson.JsonParser;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

public class ECDSA {

	public static void main(String[] args) throws Exception {
		
		String keySize = "256";
		String CertificatePath = "C:\\Users\\Admin\\IBM\\ACET12\\zero-to-hero\\JWT_Implementation\\JWT_Implementation_ES"+keySize+"_Cert.cer";
		String PrivateKeyPath = "C:\\Users\\Admin\\IBM\\ACET12\\zero-to-hero\\JWT_Implementation\\JWT_Implementation_ES"+keySize+"_PrivateKey.pem";
		String PublicKeyPath = "C:\\Users\\Admin\\IBM\\ACET12\\zero-to-hero\\JWT_Implementation\\JWT_Implementation_ES"+keySize+"_PublicKey.pem";
		String JWKSPath = "C:\\Users\\Admin\\IBM\\ACET12\\zero-to-hero\\JWT_Implementation\\JWKS.json";
		
		String token = new String(getESToken(true, keySize, CertificatePath, PrivateKeyPath, PublicKeyPath, JWKSPath));
//		String token = getESToken(false, keySize, CertificatePath, PrivateKeyPath, PublicKeyPath, JWKSPath);
		System.out.println(token);
	}
	
	public static byte[] getESToken(Boolean isCreateNew, String keySize, String CertificatePath, String PrivateKeyPath, String PublicKeyPath, String JWKSPath) {
		String instance = "EC";
		String JWSAlgorithm = "ES"+keySize;
		try {			
			ECKey esJWK = getJWKforES(isCreateNew, keySize, instance, CertificatePath, PrivateKeyPath, PublicKeyPath, JWKSPath);
			JWSHeader header = common.getJWSHeader(JWSAlgorithm);
			JWTClaimsSet claimsSet = common.getJWTClaimsSet();
			SignedJWT signedJWT = new SignedJWT(header, claimsSet);
			signedJWT.sign(new ECDSASigner(esJWK));
			
			JsonObject response = new JsonObject();
			response.addProperty("access_token", signedJWT.serialize());
			response.addProperty("scope", claimsSet.getClaims().get("scope").toString());
			response.addProperty("expires_in", 30*24*60*60);
			response.addProperty("token_type", "Bearer");
			
			return response.toString().getBytes();
		} catch (Exception e) {
			return e.getMessage().getBytes();
		}
	}
	private static ECKey getJWKforES(boolean isCreateNew, String keySize, String instance, String CertificatePath, String PrivateKeyPath, String PublicKeyPath, String JWKSPath) throws Exception {
		X509Certificate cert = null;
		PublicKey publicKey = null;
		PrivateKey privateKey = null;
		String kid = "kid-ES"+keySize;
		
		if (isCreateNew) {
			cert = createCertificate(keySize, CertificatePath, PrivateKeyPath, PublicKeyPath);
			publicKey = cert.getPublicKey();
		} else {
			cert = util.getX509Cert(CertificatePath);
			publicKey = util.getPublicKey(PublicKeyPath, instance);
		}
		privateKey = util.getPrivateKey(PrivateKeyPath, instance);
		
		Builder privateJWKBuilder = null;
		if (keySize.contains("512"))
			privateJWKBuilder =	new ECKey.Builder((new Curve("P-521")), (ECPublicKey) publicKey);
		else
			privateJWKBuilder = new ECKey.Builder((new Curve("P-"+keySize)), (ECPublicKey) publicKey);
		ECKey privateJWK = privateJWKBuilder
			    .privateKey((ECPrivateKey) privateKey)
			    .keyUse(KeyUse.SIGNATURE)
			    .algorithm(new JWSAlgorithm("ES"+keySize))
			    .keyID(kid)
			    .issueTime(new Date())
			    .build();
		
		// Created Public JWK and added x5t & x5c
		JWK publicJWK = privateJWK.toPublicJWK();
		JsonObject publicJWKjson = JsonParser.parseString(publicJWK.toJSONString()).getAsJsonObject();
		JsonArray x5c = new JsonArray();
		x5c.add(util.byteArraytoBase64String(cert.getEncoded()).replaceAll("\\u003d", ""));
		publicJWKjson.addProperty("x5t", publicJWK.computeThumbprint().toString());
		publicJWKjson.add("x5c", x5c);

		// Read existing and/or Write JWKS file
		if (isCreateNew)
			common.writePublickJWKtoFile(kid, publicJWKjson, JWKSPath);

		return privateJWK;
	}
	
	private static X509Certificate createCertificate(String keySize, String CertificatePath, String PrivateKeyPath, String PublicKeyPath) throws Exception {
		// Generate EC key pair with P-256 curve
		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
		if (keySize.contains("512"))
			keyGen.initialize((new Curve("P-521")).toECParameterSpec());
		else
			keyGen.initialize((new Curve("P-"+keySize)).toECParameterSpec());
		KeyPair keyPair = keyGen.generateKeyPair();
		PrivateKey privkey = keyPair.getPrivate();
		PublicKey publickey = keyPair.getPublic();
		
		// Generate Certificate
		X509Certificate cert = null;
		switch (keySize) {
		case "256":
			cert = util.generateCert(keyPair, "SHA256WithECDSA", AlgorithmId.EC_oid);
			break;
		case "384":
			cert = util.generateCert(keyPair, "SHA384WithECDSA", AlgorithmId.EC_oid);
			break;
		case "512":
			cert = util.generateCert(keyPair, "SHA512WithECDSA", AlgorithmId.EC_oid);
			break;
		}
		util.writeToFile(CertificatePath, util.getBase64Cert(cert));
		util.writeToFile(PrivateKeyPath, util.getBase64Key(privkey));
		util.writeToFile(PublicKeyPath, util.getBase64Key(publickey));
		return cert;
	}
}
