package com.dev.jwt;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Date;

import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.shaded.gson.JsonArray;
import com.nimbusds.jose.shaded.gson.JsonObject;
import com.nimbusds.jose.shaded.gson.JsonParser;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

public class PS {

    public static void main(String[] args) throws Exception {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

        String keySize = "256";
        String CertificatePath = "C:\\Users\\Admin\\IBM\\ACET12\\zero-to-hero\\JWT_Implementation\\JWT_Implementation_PS"+keySize+"_Cert.cer";
        String PrivateKeyPath = "C:\\Users\\Admin\\IBM\\ACET12\\zero-to-hero\\JWT_Implementation\\JWT_Implementation_PS"+keySize+"_PrivateKey.pem";
        String PublicKeyPath = "C:\\Users\\Admin\\IBM\\ACET12\\zero-to-hero\\JWT_Implementation\\JWT_Implementation_PS"+keySize+"_PublicKey.pem";
        String JWKSPath = "C:\\Users\\Admin\\IBM\\ACET12\\zero-to-hero\\JWT_Implementation\\JWKS.json";

		String token = new String(getPSToken(true, keySize, CertificatePath, PrivateKeyPath, PublicKeyPath, JWKSPath));
//		String token = getRSAToken(false, keySize, CertificatePath, PrivateKeyPath, PublicKeyPath, JWKSPath);
		System.out.print(token);
    }

    public static byte[] getPSToken(Boolean isCreateNew, String keySize, String CertificatePath, String PrivateKeyPath, String PublicKeyPath, String JWKSPath) {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        String instance = "RSA";
        String JWSAlgorithm = "PS"+keySize;
        try {
	        RSAKey rsaJWK = getJWKforPS(isCreateNew, keySize, instance, CertificatePath, PrivateKeyPath, PublicKeyPath, JWKSPath);
	        JWSHeader header = common.getJWSHeader(JWSAlgorithm);
	        JWTClaimsSet claimsSet = common.getJWTClaimsSet();
	        SignedJWT signedJWT = new SignedJWT(header, claimsSet);
	        signedJWT.sign(new RSASSASigner(rsaJWK));
	
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

    private static RSAKey getJWKforPS(boolean isCreateNew, String keySize, String instance, String CertificatePath, String PrivateKeyPath, String PublicKeyPath, String JWKSPath) throws Exception {
        X509Certificate cert = null;
        PublicKey publicKey = null;
        PrivateKey privateKey = null;
        String kid = "kid-PS"+keySize;

        if (isCreateNew) {
            cert = createCertificate(keySize, CertificatePath, PrivateKeyPath, PublicKeyPath);
            publicKey = cert.getPublicKey();
        } else {
            cert = util.getX509Cert(CertificatePath);
            publicKey = util.getPublicKey(PublicKeyPath, instance);
        }
        privateKey = util.getPrivateKey(PrivateKeyPath, instance);


        RSAKey privateJWK = new RSAKey.Builder((RSAPublicKey) publicKey)
                            .privateKey((RSAPrivateKey)privateKey)
                            .keyUse(KeyUse.SIGNATURE)
                            .algorithm(new JWSAlgorithm("PS"+keySize))
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
		// Generate the RSA key pair
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSASSA-PSS", "BC");
        keyGen.initialize(2048);
        KeyPair keyPair = keyGen.generateKeyPair();
        PrivateKey privkey = keyPair.getPrivate();
        PublicKey publickey = keyPair.getPublic();

		// Generate Certificate
		X509Certificate cert = generateCert(keyPair, "SHA"+keySize+"withRSAandMGF1");
		util.writeToFile(CertificatePath, util.getBase64Cert(cert));
		util.writeToFile(PrivateKeyPath, util.getBase64Key(privkey));
		util.writeToFile(PublicKeyPath, util.getBase64Key(publickey));
		return cert;
	}

    private static X509Certificate generateCert(final KeyPair keyPair, final String hashAlgorithm) throws Exception {
        Date since = new Date();
        Date until = new Date(since.getTime() + 365 * 86400000l);
        final ContentSigner contentSigner = new JcaContentSignerBuilder(hashAlgorithm).build(keyPair.getPrivate());
        X500NameBuilder builder = new X500NameBuilder(BCStyle.INSTANCE);
        builder.addRDN(BCStyle.NAME, "Dipanjan");
        builder.addRDN(BCStyle.C, "IN");
        builder.addRDN(BCStyle.O, "HOME");
        builder.addRDN(BCStyle.ST, "HOME");
        final X509v3CertificateBuilder certificateBuilder = new JcaX509v3CertificateBuilder(builder.build(), BigInteger.valueOf(1), since, until, builder.build(), keyPair.getPublic()).addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
        return new JcaX509CertificateConverter().setProvider(new BouncyCastleProvider()).getCertificate(certificateBuilder.build(contentSigner));
    }
}
