package com.app.config;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintWriter;
import java.io.PushbackInputStream;
import java.io.StringWriter;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.yaml.snakeyaml.Yaml;

import com.ibm.broker.javacompute.MbJavaComputeNode;
import com.ibm.broker.plugin.MbException;
import com.ibm.broker.plugin.MbMessage;
import com.ibm.broker.plugin.MbMessageAssembly;
import com.ibm.broker.plugin.MbOutputTerminal;
import com.ibm.broker.plugin.MbUserException;

/**
 * @author Dipanjan
 */

/**
 * @author Admin
 *
 */
@SuppressWarnings("unchecked")
public class Configuration extends MbJavaComputeNode {

	static HashMap<String, String> properties = new HashMap<String, String>();

	public void evaluate(MbMessageAssembly inAssembly) throws MbException {
		MbOutputTerminal out = getOutputTerminal("out");

		MbMessage inMessage = inAssembly.getMessage();
		MbMessageAssembly outAssembly = null;
		try {
			// create new message as a copy of the input
			MbMessage outMessage = new MbMessage(inMessage);
			outAssembly = new MbMessageAssembly(inAssembly, outMessage);
			// ----------------------------------------------------------
			// Add user code below

			// Reading UDPs
			String config = getUserDefinedAttribute("Config").toString();
			boolean FileNotFoundException = (boolean) getUserDefinedAttribute("FileNotFoundException");
			boolean AES_Decrypt = (boolean) getUserDefinedAttribute("AES_Decrypt");
			boolean Decrypt_Complete_File = (boolean) getUserDefinedAttribute("Decrypt_Complete_File");
			String DecryptKey = getValidValue(AES_Decrypt, "Valid AES key length: 16 bytes");

			// Loading the HashMap with Config
			String loadResult = "";
			BasicFileAttributes fileAttribute = Files.readAttributes(Paths.get(config), BasicFileAttributes.class);
			if (properties.get(config) == null
					|| !properties.get(config).contains(fileAttribute.lastModifiedTime().toString())) {
				InputStream configStream = checkStreamIsNotEmpty(new FileInputStream(new File(config)));
				if (AES_Decrypt && Decrypt_Complete_File) {
					configStream = decrypt(configStream, AES_Decrypt, DecryptKey);
				}
				if (config.endsWith(".yaml")) {
					loadResult = readYAML(configStream, AES_Decrypt, Decrypt_Complete_File, DecryptKey);
				} else if (config.endsWith(".properties")) {
					loadResult = readProperties(configStream, AES_Decrypt, Decrypt_Complete_File, DecryptKey);
				}
			}

			// if config file was loaded in HashMap, load the name of file to identify
			if (loadResult.startsWith("SUCCESS: ")) {
				properties.put(config, fileAttribute.lastModifiedTime().toString());
			} else if (loadResult.startsWith("ERROR: ") && FileNotFoundException) {
				throw new IOException(loadResult);
			}

			// End of user code
			// ----------------------------------------------------------
		} catch (Exception e) {
			// Consider replacing Exception with type(s) thrown by user code
			// Example handling ensures all exceptions are re-thrown to be handled in the
			// flow
			throw new MbUserException(this, "evaluate()", "", "", getTraceAsString(e), null);
		}
		// The following should only be changed
		// if not propagating message to the 'out' terminal
		out.propagate(outAssembly);
	}

	/**
	 * Reads a YAML file and stores them in a Hashmap. This can be used to store
	 * application & environment specific properties
	 *
	 * @return YAML reading status as String
	 * @throws Exception
	 */
	private static String readYAML(final InputStream yamlStream, final boolean AES_Decrypt,
			final boolean Decrypt_Complete_File, final String DecryptKey)
			throws Exception {
		try {
			Yaml yaml = new Yaml();
			HashMap<String, HashMap<String, Object>> yamlMap = yaml.loadAs(yamlStream, HashMap.class);
			for (String key : yamlMap.keySet()) {
				flatten(key, yamlMap.get(key), AES_Decrypt, DecryptKey);
			}
			return "SUCCESS: YAML loaded successfully";
		} catch (IOException e) {
			return "ERROR: Config file was not loaded. " + getTraceAsString(e);
		}
	}

	/**
	 * Reads a Properties file and stores them in a {@link HashMap} This can be used
	 * to store application & environment specific properties
	 *
	 * @param propsPath relative path to a .properties file
	 * @return
	 * @return Properties reading status as String
	 * @throws Exception
	 * @throws Exception
	 */
	private static String readProperties(final InputStream propsStream, final boolean AES_Decrypt,
			final boolean Decrypt_Complete_File, final String DecryptKey)
			throws Exception {
		try {
			Properties props = new Properties();
			props.load(propsStream);
			props.forEach((key, value) -> {
				try {
					properties.put(key.toString(), decrypt(value.toString(), AES_Decrypt, DecryptKey));
				} catch (Exception e) {
					throw new RuntimeException(e);
				}
			});
			return "SUCCESS: PROPS loaded successfully";
		} catch (IOException e) {
			return "ERROR: Config file was not loaded. " + getTraceAsString(e);
		}
	}

	/**
	 * Sets a specific value as a key value pair in the {@link HashMap}
	 *
	 * @param key   The key to be stored
	 * @param value The value of the key to be stored
	 */
	public static String setProperty(final String key, final String value) {
		String response = key + " stored with value " + value;
		if (getProperty(key) != null) {
			response = key + " updated with value " + value;
		}
		properties.put(key, value);
		return response;
	}

	/**
	 * Fetches a specific value against a key stored in either .properties or .yaml
	 *
	 * @param key The key of which the value is needed
	 * @return Value of the key
	 */
	public static String getProperty(final String key) {
		return properties.get(key);
	}

	/**
	 * Removes a specific key previously stored in the Hashmap
	 *
	 * @param key The key which needs to be removed from {@link HashMap}
	 * @return Value of the key
	 */
	public static String removeProperty(final String key) {
		return properties.remove(key);
	}

	/**
	 * This method is used internally to flatten the structure of Yaml and store in
	 * {@link HashMap}
	 * 
	 * @throws Exception
	 */
	private static void flatten(String key, Object obj, final boolean AES_Decrypt, final String DecryptKey) throws Exception {
		if ((obj instanceof Integer) || (obj instanceof Float) || (obj instanceof Double) || (obj instanceof String)
				|| (obj instanceof Boolean)) {
			properties.put(key, decrypt(obj.toString(), AES_Decrypt, DecryptKey));
		} else if (obj instanceof ArrayList<?>) {
			properties.put(key, decrypt(obj.toString(), AES_Decrypt, DecryptKey));
			ArrayList<?> arr = (ArrayList<?>) obj;
			for (int i = 0; i < arr.size(); i++) {
				if (arr.get(i) instanceof Map || arr.get(i) instanceof ArrayList<?>) {
					flatten(key + "[" + i + "]", arr.get(i), AES_Decrypt, DecryptKey);
				} else {
					properties.put((key + "[" + i + "]"),
							decrypt(arr.get(i).toString(), AES_Decrypt, DecryptKey));
				}
			}
		} else if (obj instanceof Map) {
			Map<String, Object> map = (Map<String, Object>) obj;
			for (String mapKey : map.keySet()) {
				if (map.get(mapKey) instanceof Map || map.get(mapKey) instanceof ArrayList<?>) {
					flatten(key + "." + mapKey, map.get(mapKey), AES_Decrypt, DecryptKey);
				} else {
					properties.put((key + "." + mapKey),
							decrypt(map.get(mapKey).toString(), AES_Decrypt, DecryptKey));
				}
			}
		}
	}

	/**
	 * This method is used internally to check if {@link InputStream} has any data
	 * to be read
	 * 
	 * @param inputStream to be checked
	 * @return {@link InputStream} as is
	 * @throws IOException
	 */
	private static InputStream checkStreamIsNotEmpty(InputStream inputStream) throws IOException {
		PushbackInputStream pushbackInputStream = new PushbackInputStream(inputStream);
		int b;
		b = pushbackInputStream.read();
		if (b == -1) {
			throw new IOException("Config file was not found");
		}
		pushbackInputStream.unread(b);
		return pushbackInputStream;
	}

	/**
	 * This method is used internally used to decrypt (if encrypted) any value read
	 * from YAML/Properties
	 */
	private static String decrypt(final String encrypted, final boolean AES_Decrypt, final String DecryptKey) throws Exception {
		if (AES_Decrypt && encrypted.startsWith("![") && encrypted.endsWith("]")) {
			SecretKeySpec skeySpec = new SecretKeySpec(DecryptKey.getBytes("UTF-8"), "AES");
			IvParameterSpec iv = new IvParameterSpec(DecryptKey.getBytes("UTF-8"));
			Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
			cipher.init(Cipher.DECRYPT_MODE, skeySpec, iv);
			byte[] original = cipher.doFinal(Base64.getDecoder().decode((encrypted.substring(2)).replaceAll("]$", "")));
			return new String(original);
		}
		return encrypted;
	}

	/**
	 * This method is used internally used to decrypt (if encrypted) the entire
	 * YAML/Properties file
	 */
	private static InputStream decrypt(final InputStream encrypted, final boolean AES_Decrypt, final String DecryptKey) throws Exception {
		SecretKeySpec skeySpec = new SecretKeySpec(DecryptKey.getBytes("UTF-8"), "AES");
		IvParameterSpec iv = new IvParameterSpec(DecryptKey.getBytes("UTF-8"));
		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
		cipher.init(Cipher.DECRYPT_MODE, skeySpec, iv);
		byte[] original = cipher.doFinal(Base64.getDecoder().decode(readAllBytes(encrypted)));
		return new ByteArrayInputStream(original);
	}

	/**
	 * This method is used internally to convert a {@link InputStream} to byte[]
	 */
	private static byte[] readAllBytes(InputStream inputStream) throws IOException {
		final int bufLen = 4 * 0x400; // 4KB
		byte[] buf = new byte[bufLen];
		int readLen;
		IOException exception = null;
		try {
			try (ByteArrayOutputStream outputStream = new ByteArrayOutputStream()) {
				while ((readLen = inputStream.read(buf, 0, bufLen)) != -1)
					outputStream.write(buf, 0, readLen);
				return outputStream.toByteArray();
			}
		} catch (IOException e) {
			exception = e;
			throw e;
		} finally {
			if (exception == null)
				inputStream.close();
			else
				try {
					inputStream.close();
				} catch (IOException e) {
					exception.addSuppressed(e);
				}
		}
	}

	/**
	 * This method is used internally to validate the AES Key and 
	 */
	private String getValidValue(final boolean AES_Decrypt, final String defaultValue) throws MbUserException {
		String value = String.format("%-16s", getUserDefinedAttribute("Decrypt_Key").toString());
		if (AES_Decrypt && (value.trim() == "" || value == defaultValue)) {
			throw new MbUserException(this, "getValidValue()", "", "", "Decrypt_Key is improper", null);
		} else if (AES_Decrypt) {
			return value;
		}
		return "";
	}

	/**
	 * This method is used internally to convert a {@link Throwable} to
	 * {@link String}
	 */
	private static String getTraceAsString(Throwable e) {
		StringWriter sw = new StringWriter();
		PrintWriter pw = new PrintWriter(sw);
		e.printStackTrace(pw);
		return sw.toString();
	}

}
