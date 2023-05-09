package com.dev.jwt;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.shaded.gson.JsonObject;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

public class HMAC {
	
    // For ArrayList
    public static List<String> algos = new ArrayList<String>();
	
	public static void main(String[] args) throws Exception {
		String keySize = "256";
		String SecretKeyPath = "C:\\Users\\Admin\\IBM\\ACET12\\zero-to-hero\\JWT_Implementation\\JWT_Implementation_HMAC"+keySize+"_Secret.pem";
		
		String token = new String(getHMACToken(true, keySize, SecretKeyPath));
//		String token = getHMACToken(false, keySize, SecretKeyPath);
		System.out.println(token);
	}
	
	public static byte[] getHMACToken(Boolean isCreateNew, String keySize, String SecretKeyPath) {
		String JWSAlgorithm = "HS"+keySize;
		try {
		byte[] sharedSecret = getSecretForHMAC(isCreateNew, SecretKeyPath);
		JWSHeader header = common.getJWSHeader(JWSAlgorithm);
		JWTClaimsSet claimsSet = common.getJWTClaimsSet();
		SignedJWT signedJWT = new SignedJWT(header, claimsSet);
		signedJWT.sign(new MACSigner(sharedSecret));

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
	private static byte[] getSecretForHMAC(Boolean isCreateNew, String SecretKeyPath) throws Exception {
		byte[] sharedSecret = null;
		if (isCreateNew) {
			sharedSecret = new byte[64];
			SecureRandom random = new SecureRandom();
			random.nextBytes(sharedSecret);
			String begin = "-----BEGIN SECRET KEY-----\n";
			String end = "\n-----END SECRET KEY-----";
			String key = new String(Base64.getMimeEncoder().encode(sharedSecret));
			util.writeToFile(SecretKeyPath, begin+key+end);
		} else {
			// sharedSecret = "H2b317l_JmQcBQ9XGhuR0ihuc8XDAHWMqhMlM7bcidnSNt_jG1hUOaCtaERgqZjr".getBytes();
			sharedSecret = util.readFromFile(SecretKeyPath).getBytes();
		}
		return sharedSecret;
	}
}