package com.kst.safenet.ssm.util;

import java.util.Arrays;
import java.util.HexFormat;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class TripleDes {

	private static final Logger logger = LoggerFactory.getLogger(TripleDes.class);
	
	public static  byte[] decryptTDES(byte[] data, byte[] key) {
		try {
			if(key.length == 16) key = concat(key, Arrays.copyOf(key, 8));
			logger.info("data : "+HexFormat.of().formatHex(data));
			logger.info("key : "+HexFormat.of().formatHex(key));
			final Cipher cipher = Cipher.getInstance("TripleDES/ECB/NoPadding");
			final SecretKeySpec keySpec = new SecretKeySpec(key, "DESede");
			cipher.init(Cipher.DECRYPT_MODE, keySpec);
			return cipher.doFinal(data);
		} catch (Exception e) {logger.error("", e);}
		return null;
	}
	
	public static byte[] encryptTDES(byte[] data, byte[] key) {
		try {
			if(key.length == 16) key = concat(key, Arrays.copyOf(key, 8));
			logger.info("data : "+HexFormat.of().formatHex(data));
			logger.info("key : "+HexFormat.of().formatHex(key));
			final Cipher cipher = Cipher.getInstance("TripleDES/ECB/NoPadding");
			final SecretKeySpec keySpec = new SecretKeySpec(key, "DESede");
			cipher.init(Cipher.ENCRYPT_MODE, keySpec);
			return cipher.doFinal(data);
		} catch (Exception e) {logger.error("", e);}
		return null;		
	}
	
	public static final byte[] concat(byte[] a, byte[] b) {
		byte[] c = new byte[a.length + b.length];
		System.arraycopy(a, 0, c, 0, a.length);
		System.arraycopy(b, 0, c, a.length, b.length);
		return c;
	}
}
