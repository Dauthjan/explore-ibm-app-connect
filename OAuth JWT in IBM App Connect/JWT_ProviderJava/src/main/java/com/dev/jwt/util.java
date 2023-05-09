package com.dev.jwt;

import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Date;

import com.ibm.security.util.ObjectIdentifier;
import com.ibm.security.x509.AlgorithmId;
import com.ibm.security.x509.CertificateAlgorithmId;
import com.ibm.security.x509.CertificateSerialNumber;
import com.ibm.security.x509.CertificateValidity;
import com.ibm.security.x509.CertificateVersion;
import com.ibm.security.x509.CertificateX509Key;
import com.ibm.security.x509.X500Name;
import com.ibm.security.x509.X509CertImpl;
import com.ibm.security.x509.X509CertInfo;
import com.nimbusds.jose.util.X509CertUtils;

public class util {

	public static byte[] combineHeaderBodyByteArray(byte[] one, byte[] two) {
		byte[] combined = new byte[one.length + 1 + two.length];
		System.arraycopy(one, 0, combined, 0, one.length);
		System.arraycopy(".".getBytes(), 0, combined, one.length, 1);
		System.arraycopy(two, 0, combined, one.length + 1, two.length);
		return combined;
	}

	public static void writeToFile(String filePath, String fileContent) throws IOException {
		File file = new File(filePath);
		file.createNewFile();
		PrintWriter printWriter = new PrintWriter(file);
		printWriter.print(fileContent);
		printWriter.close();
	}

	public static String readFromFile(String filename) throws Exception {
		File f = new File(filename);
		FileInputStream fis = new FileInputStream(f);
		DataInputStream dis = new DataInputStream(fis);
		byte[] keyBytes = new byte[(int) f.length()];
		dis.readFully(keyBytes);
		dis.close();
		return new String(keyBytes).replaceAll("-{5}[a-zA-Z ]*-{5}", "").replaceAll("\r?\n", "");
	}

	public static X509Certificate getX509Cert(String CertificatePath) throws Exception {
		String cert = readFromFile(CertificatePath);
		return X509CertUtils.parse(Base64.getMimeDecoder().decode(cert));
	}

	public static PrivateKey getPrivateKey(String privateKeyFilePath, String instance) throws Exception {
		String privateKey = readFromFile(privateKeyFilePath);
		return (KeyFactory.getInstance(instance)).generatePrivate(new PKCS8EncodedKeySpec(Base64.getMimeDecoder().decode(privateKey)));
	}

	public static PublicKey getPublicKey(String publicKeyFilePath, String instance) throws Exception {
		String publicKey = readFromFile(publicKeyFilePath);
		return KeyFactory.getInstance(instance)
				.generatePublic(new X509EncodedKeySpec(Base64.getMimeDecoder().decode(publicKey)));
	}

	public static String byteArraytoBase64String(final byte[] data) {
		Base64.Encoder enc = Base64.getEncoder();
		return enc.encodeToString(data);
	}

	public static X509Certificate generateCert(final KeyPair keyPair, final String hashAlgorithm, ObjectIdentifier oid) throws Exception {
		Date since = new Date(); // Since Now
		Date until = new Date(since.getTime() + 365 * 86400000l); // one year

		CertificateValidity interval = new CertificateValidity(since, until);
		BigInteger sn = new BigInteger(64, new SecureRandom());

		X500Name distinguishedName = new X500Name("Dipanjan", "HOME", "HOME", "IN");
		X509CertInfo info = new X509CertInfo();
		info.set(X509CertInfo.VALIDITY, interval);
		info.set(X509CertInfo.SERIAL_NUMBER, new CertificateSerialNumber(sn));
		info.set(X509CertInfo.SUBJECT, distinguishedName);
		info.set(X509CertInfo.ISSUER, distinguishedName);
		info.set(X509CertInfo.KEY, new CertificateX509Key(keyPair.getPublic()));
		info.set(X509CertInfo.VERSION, new CertificateVersion(CertificateVersion.V3));

		AlgorithmId algo = new AlgorithmId(oid);
		info.set(X509CertInfo.ALGORITHM_ID, new CertificateAlgorithmId(algo));

		// Sign the certificate to identify the algorithm that is used.
		X509CertImpl cert = new X509CertImpl(info);
		cert.sign(keyPair.getPrivate(), hashAlgorithm);

		// Update the algorithm and sign again
		algo = (AlgorithmId) cert.get(X509CertImpl.SIG_ALG);
		info.set(CertificateAlgorithmId.NAME + "." + CertificateAlgorithmId.ALGORITHM, algo);

		cert = new X509CertImpl(info);
		cert.sign(keyPair.getPrivate(), hashAlgorithm);
		return cert;
	}

	public static String getBase64Key(Key keyObj) {
		String begin = "-----BEGIN {type} KEY-----\n";
		String end = "\n-----END {type} KEY-----";
		if (keyObj instanceof PublicKey) {
			begin = begin.replace("{type}", "PUBLIC");
			end = end.replace("{type}", "PUBLIC");
		} else if (keyObj instanceof PrivateKey) {
			begin = begin.replace("{type}", "PRIVATE");
			end = end.replace("{type}", "PRIVATE");
		}
		String key = new String(Base64.getMimeEncoder().encode(keyObj.getEncoded()));

		return begin + key + end;
	}

	public static String getBase64Cert(X509Certificate certificate) throws CertificateEncodingException {
		String begin = "-----BEGIN CERTIFICATE-----\n";
		String cert = new String(Base64.getMimeEncoder().encode(certificate.getEncoded()));
		String end = "\n-----END CERTIFICATE-----";
		return begin + cert + end;
	}
}
