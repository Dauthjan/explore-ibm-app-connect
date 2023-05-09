package com.dev.jwt;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.Writer;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.UUID;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jose.shaded.gson.Gson;
import com.nimbusds.jose.shaded.gson.GsonBuilder;
import com.nimbusds.jose.shaded.gson.JsonArray;
import com.nimbusds.jose.shaded.gson.JsonElement;
import com.nimbusds.jose.shaded.gson.JsonObject;
import com.nimbusds.jose.shaded.gson.JsonParser;
import com.nimbusds.jwt.JWTClaimsSet;

public class common {

	public static JWSHeader getJWSHeader(String JWSAlgorithm) throws BadJOSEException {
		return new JWSHeader
				.Builder(new JWSAlgorithm(JWSAlgorithm))
				.type(JOSEObjectType.JWT)
				.keyID("kid-"+JWSAlgorithm)
				.build();
	}
	
	public static JWTClaimsSet getJWTClaimsSet() throws BadJOSEException {
		return new JWTClaimsSet.Builder().subject("esb_testing@clients").issuer("http://ibmace.aceisd10.com/")
				.audience("http://esbtesting.com/")
				.issueTime(new Date(new Date().getTime()))
				.notBeforeTime(new Date(new Date().getTime()))
				.expirationTime(Date.from(Instant.now().plus(30, ChronoUnit.DAYS)))
				.claim("azp", "esbtesting")
				.claim("client_id", "esb_testing")
				.claim("admin", "dauthjan")
				.claim("custom_key", "esb-testing")
				.claim("scope", "read:client_grants create:client_grants delete:client_grants update:client_grants read:client_credentials create:client_credentials update:client_credentials delete:client_credentials")
				.claim("gty", "client-credentials")
				.jwtID(UUID.randomUUID().toString()).build();
	}
	
	public static void writePublickJWKtoFile(String kid, JsonObject publicJWKjson, String JWKSPath) throws Exception {
		File f = new File(JWKSPath);
		if(!f.exists()) { 
	        byte[] json = "{\"keys\":[]}".getBytes();
	        try {
	            Files.write(Paths.get(JWKSPath), json);
	        }
	        catch (IOException ex) {
	            System.err.print(ex.getMessage());
	        }
		}
		JsonObject publicJWKSjson = JsonParser.parseString(util.readFromFile(JWKSPath)).getAsJsonObject();
		JsonArray keys = publicJWKSjson.getAsJsonArray("keys");
		for (JsonElement key : keys) {
			if (key.getAsJsonObject().get("kid").toString().contentEquals("\""+kid+"\"")) {				
				keys.remove(key);
				break;
			}
		}
		keys.add(publicJWKjson);
		Gson gson = new GsonBuilder().setPrettyPrinting().create();
		Writer writer = new FileWriter(JWKSPath);
		gson.toJson(publicJWKSjson, writer);
        writer.flush();
        writer.close();
	}
}
