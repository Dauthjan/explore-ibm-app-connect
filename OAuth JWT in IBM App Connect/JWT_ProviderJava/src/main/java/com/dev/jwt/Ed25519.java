package com.dev.jwt;

import java.security.KeyStore;
import java.security.Security;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.Date;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.Ed25519Signer;
import com.nimbusds.jose.crypto.bc.BouncyCastleProviderSingleton;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jose.jwk.gen.OctetKeyPairGenerator;
import com.nimbusds.jose.shaded.gson.JsonObject;
import com.nimbusds.jose.shaded.gson.JsonParser;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

public class Ed25519 {
	
	public static void main(String[] args) throws Exception {
		
		String PrivateKeyPath = "C:\\Users\\Admin\\IBM\\ACET12\\zero-to-hero\\JWT_Implementation\\JWT_Implementation_Ed25519_PrivateKey.pem";
		String PublicKeyPath = "C:\\Users\\Admin\\IBM\\ACET12\\zero-to-hero\\JWT_Implementation\\JWT_Implementation_Ed25519_PublicKey.pem";
		String JWKSPath = "C:\\Users\\Admin\\IBM\\ACET12\\zero-to-hero\\JWT_Implementation\\JWKS.json";
		
//		String token = getEDToken(true, PrivateKeyPath, PublicKeyPath, JWKSPath);
		String token = new String(getEDToken(false, PrivateKeyPath, PublicKeyPath, JWKSPath));
		System.out.print(token);
	}
	public static byte[] getEDToken(Boolean isCreateNew, String PrivateKeyPath, String PublicKeyPath, String JWKSPath) {
		Security.addProvider(BouncyCastleProviderSingleton.getInstance());
		String instance = "RSA";
		String JWSAlgorithm = "EdDSA";
		try {			
			OctetKeyPair edJWK = getJWKforED(isCreateNew, instance, JWSAlgorithm, PrivateKeyPath, PublicKeyPath, JWKSPath);
			JWSHeader header = common.getJWSHeader(JWSAlgorithm);
			JWTClaimsSet claimsSet = common.getJWTClaimsSet();
			JWSSigner signer = new Ed25519Signer((OctetKeyPair) edJWK);
			SignedJWT signedJWT = new SignedJWT(header, claimsSet);
			signedJWT.sign(signer);
			
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
	private static OctetKeyPair getJWKforED(boolean isCreateNew, String instance, String JwsAlgorithm, String PrivateKeyPath, String PublicKeyPath, String JWKSPath) throws Exception {
		Base64URL publicKey = null;
		Base64URL privateKey = null;
		OctetKeyPair edJWK = null;
		String kid = "kid-"+JwsAlgorithm;
		
		if (isCreateNew) {
			edJWK = new OctetKeyPairGenerator(Curve.Ed25519)
					.keyUse(KeyUse.SIGNATURE)
					.algorithm(JWSAlgorithm.EdDSA)
					.keyID(kid)
					.issueTime(new Date())
					.generate();
			privateKey = edJWK.getD();
			publicKey = edJWK.getX();
		} else {
			privateKey = Base64URL.encode(Base64.getUrlDecoder().decode(util.readFromFile(PrivateKeyPath)));
			publicKey = Base64URL.encode(Base64.getUrlDecoder().decode(util.readFromFile(PublicKeyPath)));
			KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
			edJWK = new OctetKeyPair (Curve.Ed25519,           // Curve crv
										publicKey,             // Base64URL x
										privateKey,            // Base64URL d
										KeyUse.SIGNATURE,      // KeyUse use
										null,                  // Set<KeyOperation> ops
										JWSAlgorithm.EdDSA,    // Algorithm alg
										"kid-EdDSA",           // String kid
										null,                  // URI x5u
										null,                  // Base64URL x5t
										null,                  // Base64URL x5t256
										null,                  // List<Base64> x5c
										Date.from(Instant.now().plus(30, ChronoUnit.DAYS)), // Date exp
										new Date(),            // Date nbf
										new Date(),            // Date iat
										keyStore);             // KeyStore ks
		}
		
		// Created Public JWK and added x5t & x5c
		JWK publicJWK = edJWK.toPublicJWK();
		JsonObject publicJWKjson = JsonParser.parseString(publicJWK.toJSONString()).getAsJsonObject();

		// Read existing and/or Write JWKS file
		if (isCreateNew) {
			common.writePublickJWKtoFile(kid, publicJWKjson, JWKSPath);
			util.writeToFile(PrivateKeyPath, Base64.getUrlEncoder().encodeToString(privateKey.decode()));
			util.writeToFile(PublicKeyPath, Base64.getUrlEncoder().encodeToString((publicKey.decode())));
		}
		return edJWK;
	}
}