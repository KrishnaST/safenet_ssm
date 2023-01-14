package com.kst.safenet.ssm;

import java.util.Arrays;
import java.util.HexFormat;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.kst.safenet.ssm.util.TripleDes;

public class KeyImport implements Command {

	private static final Logger logger = LoggerFactory.getLogger(CommandProcessor.class);
	private static final byte[] lmk = HexFormat.of().parseHex(Application.properties.getProperty("lmk"));
	private static final byte[] zeroes = HexFormat.of().parseHex("0000000000000000");
	
	//EE0200 00 050810020032 01 00 10 92374B4E894B4F54BC2F87072A2A998F
	//EE0200 00 050810020032 02 00 10 02E07E6669D0FD410D39318C2BB0100D
	//EE0200 00 1111 31814B249DC6A2D2D2E4B2D7D098CD5D B22E15
	//EE0200 00 1111 31940099E51A8CE589084B56FD3D50FE 1AF4B2
	@Override
	public final String execute(String request) {
		final String command = request.substring(0,6);
		logger.info("command : "+command);
		final String zmkIndex = request.substring(18,20);
		logger.info("zmkIndex : "+zmkIndex);
		final String keyType = request.substring(20,22);
		logger.info("keyType : "+keyType);
		final String key_zmk = request.substring(26);
		logger.info("key_zmk : "+key_zmk);
		final String zmk = Application.properties.getProperty("index"+zmkIndex);
		logger.info("zmk at index "+zmkIndex+" : "+zmk);
		final byte[] key = TripleDes.decryptTDES(HexFormat.of().parseHex(key_zmk), HexFormat.of().parseHex(zmk));
		logger.info("key : "+HexFormat.of().formatHex(key));
		final byte[] key_lmk = TripleDes.encryptTDES(key, lmk);
		logger.info("key_lmk : "+HexFormat.of().formatHex(key_lmk));
		final byte[] kcv = Arrays.copyOfRange(TripleDes.encryptTDES(zeroes, key), 0, 3);
		return command + "001111" + HexFormat.of().formatHex(key_lmk) + HexFormat.of().formatHex(kcv);
	}

}
