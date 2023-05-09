package com.dev.jwt;

import java.text.ParseException;

import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jose.shaded.gson.JsonObject;
import com.nimbusds.jose.util.Base64;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.PlainJWT;

public class None {

	public static void main(String[] args) throws ParseException, BadJOSEException {
		String token = new String(getNoneToken());
		System.out.print(token);
		
		// manual parsing
		if (!token.endsWith(".")) { token = token + "."; }
		String[] jwtSegments = token.split("\\.");
		System.out.println(jwtSegments[0]);
		System.out.println(jwtSegments[1]);
		System.out.println(new String(java.util.Base64.getUrlDecoder().decode(jwtSegments[0])));
		System.out.println(new String(java.util.Base64.getUrlDecoder().decode(jwtSegments[1])));

		// nimbus parsing
		JWT parsedJwt = PlainJWT.parse(token);
		System.out.println(parsedJwt.getHeader());
		System.out.println(parsedJwt.getJWTClaimsSet());
	}
	
	public static byte[] getNoneToken() {
		try {
			Base64 header = getJWSHeader();
			Base64 claimsSet = Base64.encode(common.getJWTClaimsSet().toString());
			JsonObject response = new JsonObject();
			response.addProperty("access_token", header + "." + claimsSet + ".");
			response.addProperty("scope", "read:client_grants create:client_grants delete:client_grants update:client_grants read:client_credentials create:client_credentials update:client_credentials delete:client_credentials");
			response.addProperty("expires_in", 30*24*60*60);
			response.addProperty("token_type", "Bearer");
			return response.toString().getBytes();
		} catch (BadJOSEException e) {
			return e.getMessage().getBytes();
		}
	}

	private static Base64 getJWSHeader() {
		String PlainJWTHeader = "{\r\n" + 
				"	\"kid\": \"kid-NONE\",\r\n" + 
				"	\"typ\": \"JWT\",\r\n" + 
				"	\"alg\": \"none\"\r\n" + 
				"}";
		return Base64.encode(PlainJWTHeader);
	}
}
