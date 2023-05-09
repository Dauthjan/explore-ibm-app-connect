package com.dev.jwt;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Base64;
import java.util.Calendar;
import java.util.Date;
import java.util.TimeZone;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import com.google.crypto.tink.subtle.Ed25519Verify;
import com.ibm.broker.javacompute.MbJavaComputeNode;
import com.ibm.broker.plugin.MbElement;
import com.ibm.broker.plugin.MbException;
import com.ibm.broker.plugin.MbMessage;
import com.ibm.broker.plugin.MbMessageAssembly;
import com.ibm.broker.plugin.MbOutputTerminal;
import com.ibm.broker.plugin.MbPolicy;
import com.ibm.broker.plugin.MbUserException;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.Ed25519Verifier;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.crypto.bc.BouncyCastleFIPSProviderSingleton;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKException;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.shaded.gson.JsonArray;
import com.nimbusds.jose.shaded.gson.JsonObject;
import com.nimbusds.jose.shaded.gson.JsonParser;
import com.nimbusds.jose.util.X509CertUtils;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.proc.BadJWTException;

public class JWTValidation extends MbJavaComputeNode {

    private static JWKSet provider = null;
    private static Date nextProviderRefresh = null;
    private static final Pattern claimPattern = Pattern.compile("^([^!=><\\s]+)\\s+(==|>=|<=|!=|>|<|IN|in|NOTIN|notin)\\s+([^!=><]+)$");
    private static final Pattern clientIDPattern = Pattern.compile("^([^!=><]+)\\s+(==|IN|in)\\s+([^!=><]+)$");
    private static final String comma = "\\s*,\\s*";
    private static final String semicolon = "\\s*;\\s*";

    public void evaluate(MbMessageAssembly inAssembly) throws MbException {

        MbOutputTerminal out = getOutputTerminal("out");
        MbOutputTerminal alt = getOutputTerminal("alternate");
        MbMessage inMessage = inAssembly.getMessage();
        MbMessageAssembly outAssembly = null;
        try {
            // create new message as a copy of the input
            MbMessage outMessage = new MbMessage(inMessage);
            outAssembly = new MbMessageAssembly(inAssembly, outMessage);
            // ----------------------------------------------------------
            // Add user code below

            // Reading UDP
            String PolicyProfile = getUserDefinedAttribute("PolicyProfile").toString();
//            String PolicyProfile = inMessage.getRootElement().getFirstElementByPath("HTTPInputHeader/X-Policy").getValueAsString(); // enable this line for unit testing

            // Reading Custom JWT Policy
            MbPolicy retrievedPolicy = MbPolicy.getPolicy("UserDefined", PolicyProfile);
            String HTTP_Methods_Allowed = retrievedPolicy.getPropertyValueAsString("HTTP_Methods_Allowed");
            String JWT_location_in_API_requests = retrievedPolicy.getPropertyValueAsString("JWT_location_in_API_requests");
            String JWT_Signing_Method = retrievedPolicy.getPropertyValueAsString("JWT_Signing_Method");
            boolean Key_Base64_Encoded = Boolean.parseBoolean(retrievedPolicy.getPropertyValueAsString("Key_Base64_Encoded")) || false;
            boolean Skip_Client_Id_Validation = Boolean.parseBoolean(retrievedPolicy.getPropertyValueAsString("Skip_Client_Id_Validation"));
            String Client_ID_Expression = retrievedPolicy.getPropertyValueAsString("Client_ID_Expression");
            boolean Validate_Audience_Claim = Boolean.parseBoolean(retrievedPolicy.getPropertyValueAsString("Validate_Audience_Claim"));
            boolean Audience_Claim_Mandatory = Boolean.parseBoolean(retrievedPolicy.getPropertyValueAsString("Audience_Claim_Mandatory"));
            String Audience_Claim_Values = retrievedPolicy.getPropertyValueAsString("Audience_Claim_Values");
            boolean Expiration_Claim_Mandatory = Boolean.parseBoolean(retrievedPolicy.getPropertyValueAsString("Expiration_Claim_Mandatory"));
            boolean Not_Before_Claim_Mandatory = Boolean.parseBoolean(retrievedPolicy.getPropertyValueAsString("Not_Before_Claim_Mandatory"));
            boolean Validate_Custom_Claim = Boolean.parseBoolean(retrievedPolicy.getPropertyValueAsString("Validate_Custom_Claim"));
            String Mandatory_Custom_Claim_Validations = retrievedPolicy.getPropertyValueAsString("Mandatory_Custom_Claim_Validations");
            boolean Advance_Apply_configuration_to_all_API_method_and_resources = Boolean.parseBoolean(retrievedPolicy.getPropertyValueAsString("Advance_Apply_configuration_to_all_API_method_and_resources"));
            String Advance_Apply_configuration_to_specific_API_method_and_resources = retrievedPolicy.getPropertyValueAsString("Advance_Apply_configuration_to_specific_API_method_and_resources");

            // Reading X-Original-HTTP-Command to validate if policy should be applied
            String httpCommand = inMessage.getRootElement().getFirstElementByPath("HTTPInputHeader/X-Original-HTTP-Command").getValueAsString().replace(" HTTP/1.1", "");
            String host = inMessage.getRootElement().getFirstElementByPath("HTTPInputHeader/Host").getValueAsString();
            String httpMethod = httpCommand.split("\\s")[0];
            String httpURI = httpCommand.split("\\s")[1].substring(httpCommand.split("\\s")[1].indexOf(host)+host.length());
            String[] applyConfigurationToSpecificAPIMethodAndResources = Advance_Apply_configuration_to_specific_API_method_and_resources.split(semicolon);
            boolean policyToApply = false || Advance_Apply_configuration_to_all_API_method_and_resources;
            if (!policyToApply && Advance_Apply_configuration_to_specific_API_method_and_resources.length() != 0) {
                for (String applyConfigurationToSpecificAPIMethodAndResource : applyConfigurationToSpecificAPIMethodAndResources) {
                    String httpMethodForValidation = applyConfigurationToSpecificAPIMethodAndResource.split("\\s")[0];
                    String httpURLForValidation = applyConfigurationToSpecificAPIMethodAndResource.split("\\s")[1].replace("*", ".*");
                    policyToApply = httpMethod.equals(httpMethodForValidation) && Pattern.compile(httpURLForValidation).matcher(httpURI).matches();
                    if (policyToApply)
                        break;
                }
            }

            // Check if HTTP Methods Allowed is enabled
            if (HTTP_Methods_Allowed != null && HTTP_Methods_Allowed.length() != 0 && !HTTP_Methods_Allowed.contains(httpMethod)) {
                MbMessage localEnv = inAssembly.getLocalEnvironment();
                MbMessage outLocalEnv = new MbMessage(localEnv);
                outLocalEnv.getRootElement().evaluateXPath("?Destination/?HTTP/?ReplyStatusCode [set-value(405)]");
                outAssembly = new MbMessageAssembly(inAssembly, outLocalEnv, inAssembly.getExceptionList(), inAssembly.getMessage());
                alt.propagate(outAssembly);
                return;
            }

            // Applying JWT validation if Policy should be applied
            if ((Advance_Apply_configuration_to_all_API_method_and_resources) || policyToApply) {
                // Reading token from HTTP Request
                MbElement tokenElement;
                tokenElement = inMessage.getRootElement().getFirstElementByPath(JWT_location_in_API_requests);
                if (tokenElement == null)
                    throw new GeneralSecurityException("JWT expected but not found.");
                String token = tokenElement.getValueAsString().replace("Bearer ", "");

                // Getting JWKS (if in use) and extracting JWK using KeyID
                JWT jwt = null;
                if (!JWT_Signing_Method.toUpperCase().contentEquals("NONE")) {

                    // get JWK (only if JWKS is used)
                    SignedJWT signedJWT = SignedJWT.parse(token);
                    String JWT_Key_origin = retrievedPolicy.getPropertyValueAsString("JWT_Key_origin");
                    String JWKS_URL_or_Key = retrievedPolicy.getPropertyValueAsString("JWKS_URL_or_Key");
                    JWK jwk = getJWK(retrievedPolicy, signedJWT);

                    // Creating verifier
                    JWSVerifier verifier = getVerifier(token, JWT_Signing_Method, JWT_Key_origin, JWKS_URL_or_Key, Key_Base64_Encoded, signedJWT, jwk);

                    // Verifying signature
                    if (!( JWT_Signing_Method.toUpperCase().contentEquals("ED") && ( JWT_Key_origin.toUpperCase().contentEquals("CERT") || JWT_Key_origin.toUpperCase().contentEquals("KEY") ))) {
                        boolean verified = signedJWT.verify(verifier);
                        if (!verified) {
                            // retry for JWKS (it may be due to rotating Key)
                            if (JWT_Key_origin.toUpperCase().contentEquals("JWKS")) {
                                nextProviderRefresh = null;
                                jwk = getJWK(retrievedPolicy, signedJWT);
                                verifier = getVerifier(token, JWT_Signing_Method, JWT_Key_origin, JWKS_URL_or_Key, Key_Base64_Encoded, signedJWT, jwk);
                                verified = signedJWT.verify(verifier);
                            }
                            if (!verified)
                                throw new GeneralSecurityException("Signature check failed.");
                        }
                    }
                    jwt = signedJWT;
                } else {
                    if (!token.endsWith(".")) {token = token + ".";}
                    jwt = PlainJWT.parse(token);
                }

                // Client_Id Validation if required
                if (!Skip_Client_Id_Validation && Client_ID_Expression != null && Client_ID_Expression.length() != 0) {
                    String[] clienIDExpression = PatternBreakdown(Client_ID_Expression, clientIDPattern);
                    if (!clienIDExpression[2].contains(jwt.getJWTClaimsSet().getStringClaim(clienIDExpression[0])))
                        throw new BadJWTException("Invalid token - Client ID "+jwt.getJWTClaimsSet().getStringClaim(clienIDExpression[0])+" is not authorized.");
                }

                // Check for Expiration Claim
                DateFormat format = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSSzzz");
                format.setTimeZone(TimeZone.getTimeZone("Etc/UTC"));
                if (Expiration_Claim_Mandatory && jwt.getJWTClaimsSet().getExpirationTime() == null)
                    throw new BadJWTException("Invalid token - Expiration Claim not found.");
                else if (jwt.getJWTClaimsSet().getExpirationTime() != null && jwt.getJWTClaimsSet().getExpirationTime().before(Calendar.getInstance().getTime()))
                    throw new BadJWTException("The token has expired on " + format.format(jwt.getJWTClaimsSet().getExpirationTime()));

                // Check for Not_Before Claim
                if (Not_Before_Claim_Mandatory && jwt.getJWTClaimsSet().getNotBeforeTime() == null)
                    throw new BadJWTException("Invalid token - Not Before Claim not found.");
                else if (jwt.getJWTClaimsSet().getNotBeforeTime() != null && jwt.getJWTClaimsSet().getNotBeforeTime().after(Calendar.getInstance().getTime()))
                    throw new BadJWTException("The token can be used after " + format.format(jwt.getJWTClaimsSet().getNotBeforeTime()));

                // Validating Audience Claim if required
                if (Validate_Audience_Claim) {
                    if (jwt.getJWTClaimsSet().getAudience().isEmpty())
                        throw new BadJWTException("Invalid token - The token does not contain any Audience Claim");
                    if (Audience_Claim_Mandatory && Audience_Claim_Values != null && Audience_Claim_Values.length() != 0) {
                        boolean found = false;
                        String[] audienceClaimValues = Audience_Claim_Values.split(comma);
                        for (String audienceClaim : audienceClaimValues) {
                            if (jwt.getJWTClaimsSet().getAudience().contains(audienceClaim)) { found = true; break; }
                        }
                        if (!found)
                            throw new BadJWTException("Invalid token - Audience Claim " + jwt.getJWTClaimsSet().getAudience() + " does not contain any authorized audience.");
                    }
                }
                if (Validate_Custom_Claim && Mandatory_Custom_Claim_Validations != null && Mandatory_Custom_Claim_Validations.length() != 0) {
                    String[] mandatoryCustomClaimValidations = Mandatory_Custom_Claim_Validations.split(semicolon);
                    for (String mandatoryCustomClaimValidation : mandatoryCustomClaimValidations) {
                        String[] keyOperatorValue = PatternBreakdown(mandatoryCustomClaimValidation, claimPattern);
                        if (jwt.getJWTClaimsSet().getClaim(keyOperatorValue[0]) != null) {
                            switch (keyOperatorValue[1]) {
                            case "<":
                                if (Double.parseDouble(jwt.getJWTClaimsSet().getStringClaim(keyOperatorValue[0])) >= Double.parseDouble((keyOperatorValue[2])))
                                    throw new BadJWTException("Invalid token - validation failed due to Mandatory Custom Claim Validations " + mandatoryCustomClaimValidation + " value passed is " + jwt.getJWTClaimsSet().getStringClaim(keyOperatorValue[0]));
                                break;
                            case ">":
                                if (Double.parseDouble(jwt.getJWTClaimsSet().getStringClaim(keyOperatorValue[0])) <= Double.parseDouble(keyOperatorValue[2]))
                                    throw new BadJWTException("Invalid token - validation failed due to Mandatory Custom Claim Validations " + mandatoryCustomClaimValidation + " value passed is " + jwt.getJWTClaimsSet().getStringClaim(keyOperatorValue[0]));
                                break;
                            case "<=":
                                if (Double.parseDouble(jwt.getJWTClaimsSet().getStringClaim(keyOperatorValue[0])) > Double.parseDouble(keyOperatorValue[2]))
                                    throw new BadJWTException("Invalid token - validation failed due to Mandatory Custom Claim Validations " + mandatoryCustomClaimValidation + " value passed is " + jwt.getJWTClaimsSet().getStringClaim(keyOperatorValue[0]));
                                break;
                            case ">=":
                                if (Double.parseDouble(jwt.getJWTClaimsSet().getStringClaim(keyOperatorValue[0])) < Double.parseDouble(keyOperatorValue[2]))
                                    throw new BadJWTException("Invalid token - validation failed due to Mandatory Custom Claim Validations " + mandatoryCustomClaimValidation + " value passed is " + jwt.getJWTClaimsSet().getStringClaim(keyOperatorValue[0]));
                                break;
                            case "==":
                                if (!jwt.getJWTClaimsSet().getStringClaim(keyOperatorValue[0]).equals(keyOperatorValue[2]))
                                    throw new BadJWTException("Invalid token - validation failed due to Mandatory Custom Claim Validations " + mandatoryCustomClaimValidation + " value passed is " + jwt.getJWTClaimsSet().getStringClaim(keyOperatorValue[0]));
                                break;
                            case "!=":
                                if (jwt.getJWTClaimsSet().getStringClaim(keyOperatorValue[0]).equals(keyOperatorValue[2]))
                                    throw new BadJWTException("Invalid token - validation failed due to Mandatory Custom Claim Validations " + mandatoryCustomClaimValidation + " value passed is " + jwt.getJWTClaimsSet().getStringClaim(keyOperatorValue[0]));
                                break;
                            case "in":
                                String[] clamvalues = keyOperatorValue[2].split(comma);
                                boolean match = false;
                                for (String clamvalue : clamvalues) {
                                    if (clamvalue.contentEquals(jwt.getJWTClaimsSet().getStringClaim(keyOperatorValue[0]))) { match = true; break; }
                                }
                                if (!match)
                                    throw new BadJWTException("Invalid token - validation failed due to Mandatory Custom Claim Validations " + mandatoryCustomClaimValidation + " value passed is " + jwt.getJWTClaimsSet().getStringClaim(keyOperatorValue[0]));
                                break;
                            case "notin":
                                String[] noclamvalues = keyOperatorValue[2].split(comma);
                                boolean nomatch = false;
                                for (String noclamvalue : noclamvalues) {
                                    if (noclamvalue.contentEquals(jwt.getJWTClaimsSet().getStringClaim(keyOperatorValue[0]))) { nomatch = true; break; }
                                }
                                if (nomatch)
                                    throw new BadJWTException("Invalid token - validation failed due to Mandatory Custom Claim Validations " + mandatoryCustomClaimValidation + " value passed is " + jwt.getJWTClaimsSet().getStringClaim(keyOperatorValue[0]));
                                break;
                            }
                        } else
                            throw new BadJWTException("Invalid token - validation failed due to Mandatory Custom Claim missing " + keyOperatorValue[0]);
                    }
                }
            }
            // End of user code
            // ----------------------------------------------------------
        } catch (Exception e) {
            throw new MbUserException(this, "evaluate()", "", "", e.toString(), null);
        }
        out.propagate(outAssembly);
    }

    /**
    * Retrieve JWK from the JWKS
    * @param retrievedPolicy {@link MbPolicy} JWT UserDefined Policy
    * @param signedJWT {@link SignedJWT} parsed signed JWT
    * @throws Exception
    */
    private JWK getJWK(MbPolicy retrievedPolicy, SignedJWT signedJWT) throws Exception {
        JWK jwk = null;
        String JWT_Key_origin = retrievedPolicy.getPropertyValueAsString("JWT_Key_origin");
        String JWKS_URL_or_Key = retrievedPolicy.getPropertyValueAsString("JWKS_URL_or_Key");
        if (JWT_Key_origin.toUpperCase().contentEquals("JWKS")) {
            if (JWKS_URL_or_Key.startsWith("file://"))
                provider = JWKSet.load(new File(JWKS_URL_or_Key.replace("file://", "")));
            else if (JWKS_URL_or_Key.startsWith("http://") || JWKS_URL_or_Key.startsWith("https://")) {
                if (nextProviderRefresh == null || nextProviderRefresh.before(Calendar.getInstance().getTime())) {
                    getProviderFromURL(retrievedPolicy);
                }
            } else {
                // check if JWK or JWKS was provided
                JsonObject jsonObj = JsonParser.parseString(JWKS_URL_or_Key).getAsJsonObject();
                if(jsonObj.get("keys") == null) {
                    JsonArray keys = new JsonArray();
                    keys.add(jsonObj);
                    JsonObject data = new JsonObject();
                    data.add("keys", keys);
                    provider = JWKSet.load(new ByteArrayInputStream(data.toString().getBytes(StandardCharsets.UTF_8)));
                } else {
                    provider = JWKSet.load(new ByteArrayInputStream(JWKS_URL_or_Key.getBytes(StandardCharsets.UTF_8)));
                }
            }
            jwk = provider.getKeyByKeyId(signedJWT.getHeader().getKeyID());
            if (jwk == null) {
                // it may be because of rotating kid in JWT => retry
                getProviderFromURL(retrievedPolicy);
                jwk = provider.getKeyByKeyId(signedJWT.getHeader().getKeyID());
                if (jwk == null)
                    throw new JWKException("No JWK found for the given kid "+signedJWT.getHeader().getKeyID());
            }
        }
        return jwk;
    }

    /**
    * Fetch JWKS from URL
    * @param retrievedPolicy {@link MbPolicy} JWT UserDefined Policy
    * @throws Exception
    */
    private void getProviderFromURL(MbPolicy retrievedPolicy) throws Exception {
        long JWKS_Caching_TTL = Long.valueOf(Integer.parseInt(retrievedPolicy.getPropertyValueAsString("JWKS_Caching_TTL")) * 60 * 1000);
        nextProviderRefresh = new Date(System.currentTimeMillis() + JWKS_Caching_TTL);
        Integer JWKS_Service_connection_timeout = Integer.parseInt(retrievedPolicy.getPropertyValueAsString("JWKS_Service_connection_timeout")) * 1000;
        provider = JWKSet.load(new URL(retrievedPolicy.getPropertyValueAsString("JWKS_URL_or_Key")), JWKS_Service_connection_timeout, JWKS_Service_connection_timeout, 1000000);
    }

    /**
    * Depending on the JWS algorithm, get the JWSverifier<br>
    * <b>For ED Verification with Certificate or Key,
    * the verification is done here</b>
    * @param token {@link String} JWT
    * @param JWT_Signing_Method {@link String} Signing algorithm
    * @param JWT_Key_origin {@link String} JWKS/CERT/KEY
    * @param JWKS_URL_or_Key {@link String} URL/FILEPATH/TEXT
    * @param Key_Base64_Encoded {@link Boolean} only used for HMAC (default  is false)
    * @param signedJWT {@link SignedJWT} parsed signed token
    * @param jwk {@link JWK} JSON Web Key only used for JWT_Key_origin == JWKS
    * @return {@link JWSVerifier}
    * @throws Exception
    */
    private JWSVerifier getVerifier(String token, String JWT_Signing_Method, String JWT_Key_origin, String JWKS_URL_or_Key, boolean Key_Base64_Encoded, SignedJWT signedJWT, JWK jwk) throws Exception {
        JWSVerifier verifier = null;
        switch (JWT_Signing_Method.toUpperCase()) {
            case "RSA":
            case "PS":
                PublicKey rsaPublicKey = null;
                if (JWT_Key_origin.toUpperCase().contentEquals("JWKS"))
                    verifier = new RSASSAVerifier((RSAKey) jwk);
                else if (JWT_Key_origin.toUpperCase().contentEquals("CERT")) {
                    if (JWKS_URL_or_Key.startsWith("file://"))
                        rsaPublicKey = getPublicKeyFromX509Cert(getFromFile(JWKS_URL_or_Key));
                    else
                        rsaPublicKey = getPublicKeyFromX509Cert(JWKS_URL_or_Key);
                    verifier = new RSASSAVerifier((RSAPublicKey) rsaPublicKey);
                } else if (JWT_Key_origin.toUpperCase().contentEquals("KEY")) {
                    if (JWKS_URL_or_Key.startsWith("file://"))
                        rsaPublicKey = getPublicKey(getFromFile(JWKS_URL_or_Key), "RSA");
                    else
                        rsaPublicKey = getPublicKey(JWKS_URL_or_Key, "RSA");
                    verifier = new RSASSAVerifier((RSAPublicKey) rsaPublicKey);
                }
                if (JWT_Signing_Method.toUpperCase().contentEquals("PS"))
                    verifier.getJCAContext().setProvider(BouncyCastleFIPSProviderSingleton.getInstance());
                break;
            case "HMAC":
                if (Key_Base64_Encoded)
                    if (JWKS_URL_or_Key.startsWith("file://"))
                        verifier = new MACVerifier(Base64.getMimeDecoder().decode(getFromFile(JWKS_URL_or_Key)));
                    else
                        verifier = new MACVerifier(Base64.getMimeDecoder().decode(JWKS_URL_or_Key));
                else
                    if (JWKS_URL_or_Key.startsWith("file://"))
                        verifier = new MACVerifier(getFromFile(JWKS_URL_or_Key));
                    else
                        verifier = new MACVerifier(JWKS_URL_or_Key);
                break;
            case "ES":
                PublicKey ecPublicKey = null;
                if (JWT_Key_origin.toUpperCase().contentEquals("JWKS"))
                    verifier = new ECDSAVerifier((ECKey) jwk);
                else if (JWT_Key_origin.toUpperCase().contentEquals("CERT")) {
                    if (JWKS_URL_or_Key.startsWith("file://"))
                        ecPublicKey = getPublicKeyFromX509Cert(getFromFile(JWKS_URL_or_Key));
                    else
                        ecPublicKey = getPublicKeyFromX509Cert(JWKS_URL_or_Key);
                    verifier = new ECDSAVerifier((ECPublicKey) ecPublicKey);
                } else if (JWT_Key_origin.toUpperCase().contentEquals("KEY")) {
                    if (JWKS_URL_or_Key.startsWith("file://"))
                        ecPublicKey = getPublicKey(getFromFile(JWKS_URL_or_Key), "EC");
                    else
                        ecPublicKey = getPublicKey(JWKS_URL_or_Key, "EC");
                    verifier = new ECDSAVerifier((ECPublicKey) ecPublicKey);
                }
                break;
            case "ED":
                String edPublicKey = null;
                if (JWT_Key_origin.toUpperCase().contentEquals("JWKS")) {
                    verifier = new Ed25519Verifier((OctetKeyPair) jwk);
                } else if (JWT_Key_origin.toUpperCase().contentEquals("CERT") || JWT_Key_origin.toUpperCase().contentEquals("KEY")) {
                    if (JWT_Key_origin.toUpperCase().contentEquals("CERT")) {
                        if (JWKS_URL_or_Key.startsWith("file://"))
                            edPublicKey = Base64.getEncoder().encodeToString(getPublicKeyFromX509Cert(getFromFile(JWKS_URL_or_Key)).getEncoded());
                        else
                            edPublicKey = Base64.getEncoder().encodeToString(getPublicKeyFromX509Cert(JWKS_URL_or_Key).getEncoded());
                    } else if (JWT_Key_origin.toUpperCase().contentEquals("KEY")) {
                        if (JWKS_URL_or_Key.startsWith("file://"))
                            edPublicKey = getFromFile(JWKS_URL_or_Key);
                        else
                            edPublicKey = JWKS_URL_or_Key;
                    }
                    String[] tokenSegments = token.split("\\.");
                    byte[] tokenData = (tokenSegments[0]+"."+tokenSegments[1]).getBytes();
                    Ed25519Verify verifier_alt = new Ed25519Verify(Base64.getUrlDecoder().decode(edPublicKey.getBytes()));
                    verifier_alt.verify(signedJWT.getSignature().decode(), tokenData);
                }
                break;
            }
        return verifier;
    }

    /**
    * Reads a public key from a file
    * @param filename name of the file to read as {@link String}
    * @return the read content as {@link String}
    * @throws Exception
    */
    private String getFromFile(String filename) throws Exception {
        File f = new File(filename.replace("file://", ""));
        FileInputStream fis = new FileInputStream(f);
        DataInputStream dis = new DataInputStream(fis);
        byte[] keyBytes = new byte[(int) f.length()];
        dis.readFully(keyBytes);
        dis.close();
        return new String(keyBytes).replaceAll("-{5}[a-zA-Z ]*-{5}", "").replaceAll("\r?\n", "");
    }

    /**
    * Reads a certificate as {@link String} and returns a {@link PublicKey}
    * @param cert as {@link String}
    * @return {@link PublicKey}
    * @throws CertificateException
    */
    private static PublicKey getPublicKeyFromX509Cert(String cert) throws CertificateException {
        return (X509CertUtils.parse(Base64.getMimeDecoder().decode(cert))).getPublicKey();
        // return CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(Base64.getMimeDecoder().decode(cert))).getPublicKey();
    }

    /**
    * Reads a public key as {@link String} and returns the {@link PublicKey}
    * @param publicKey as {@link String}
    * @param instance {@link KeyFactory} instance
    * @return {@link PublicKey}
    * @throws Exception
    */
    public static PublicKey getPublicKey(String publicKey, String instance) throws Exception {
        return KeyFactory.getInstance(instance).generatePublic(new X509EncodedKeySpec(Base64.getMimeDecoder().decode(publicKey)));
    }

    /**
    * Reads an expression and breaks down to 3 segments
    * Key operator Value
    * @param string Content to breakdown using regex
    * @param pattern Regular Expression
    * @return the three segments from the {@link String} as {@link Arrays}
    */
    private static String[] PatternBreakdown(String string, Pattern pattern) {
        Matcher matcher = pattern.matcher(string);
        if (matcher.matches()) {
            String[] keyOperatorValue = new String[3];
            keyOperatorValue[0] = matcher.group(1).trim();
            keyOperatorValue[1] = matcher.group(2).trim().toLowerCase();
            keyOperatorValue[2] = matcher.group(3).trim();
            return keyOperatorValue;
        }
        return null;
    }
}