package com.kst.safenet.ssm;

import java.security.SecureRandom;
import java.util.Arrays;
import java.util.HexFormat;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.kst.safenet.ssm.util.TripleDes;

public class GenerateTpkUnderTmk implements Command {

	private static final Logger logger = LoggerFactory.getLogger(CommandProcessor.class);
	private static final SecureRandom random = new SecureRandom();
	private static final byte[] lmk = HexFormat.of().parseHex(Application.properties.getProperty("lmk"));
	private static final byte[] tmk = HexFormat.of().parseHex(Application.properties.getProperty("tmk"));
	private static final byte[] zeroes = HexFormat.of().parseHex("0000000000000000");
	
	
	//EE0400 00 1113 FF49E645D0AECC1D6E488BB9CCACCC79 0200
	//EE0400 00 01 10BFDF5293F638D395384F7B80932F5CCD 11 1140607BFE6CCD61C6B356EECA72079F98 116AD0
	@Override
	public final String execute(String request) {
		final String command = request.substring(0,6);
		logger.info("command : "+command);
		final String ktmSpec = request.substring(8,12);
		logger.info("ktmSpec : "+ktmSpec);
		final String tmk_lmk = request.substring(12, 44);
		logger.info("tmk_lmk : "+tmk_lmk);
		final String keyType = request.substring(44);
		logger.info("keyType : "+keyType);
		//final byte[] tmk = TripleDes.decryptTDES(HexFormat.of().parseHex(tmk_lmk), lmk);
		//logger.info("tmk : "+HexFormat.of().formatHex(tmk));
		final byte[] tpk = new byte[16];
		random.nextBytes(tpk);
		logger.info("tpk : "+HexFormat.of().formatHex(tpk));
		final byte[] tpk_tmk = TripleDes.encryptTDES(tpk, tmk);
		logger.info("tpk_tmk : "+HexFormat.of().formatHex(tpk_tmk));
		final byte[] tpk_lmk = TripleDes.encryptTDES(tpk, lmk);
		logger.info("tpk_lmk : "+HexFormat.of().formatHex(tpk_lmk));
		final byte[] kcv = Arrays.copyOfRange(TripleDes.encryptTDES(zeroes, tpk), 0, 3);
		return command + "0001" + "10" + HexFormat.of().formatHex(tpk_tmk) + "1111" + HexFormat.of().formatHex(tpk_lmk) + HexFormat.of().formatHex(kcv);
	}

}
