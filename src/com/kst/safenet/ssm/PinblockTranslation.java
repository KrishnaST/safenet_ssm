package com.kst.safenet.ssm;

import java.util.HexFormat;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.kst.safenet.ssm.util.TripleDes;

public class PinblockTranslation implements Command {

	private static final Logger logger = LoggerFactory.getLogger(CommandProcessor.class);
	private static final byte[] lmk = HexFormat.of().parseHex(Application.properties.getProperty("lmk"));
	
	//EE0602 00    39B4350138B371AC 111146999C7CE9D857F1E7039F274B87B925 01 817102706308 01 11118019AA481BCB047FCD14873C101B43D3
	//ee0602 00 efe7ad4dc949099a 111146999c7ce9d857f1e7039f274b87b92501559100009565011111bcd534dfb9ba5146773f0e970925ed0c
	//EE0602 00 1432FFD885733F7E
	@Override
	public final String execute(String request) {
		final String command = request.substring(0,6);
		logger.info("command : "+command);
		final String pinblock = request.substring(8,24);
		logger.info("pinblock : "+pinblock);
		final String sourceEncTpk = request.substring(28, 60);
		logger.info("sourceEncTpk : "+sourceEncTpk);
		final String pan12 = request.substring(62, 74);
		logger.info("pan12 : "+pan12);
		final String targetEncZpk = request.substring(80);
		logger.info("targetEncZpk : "+targetEncZpk);
		
		final byte[] tpk = TripleDes.decryptTDES(HexFormat.of().parseHex(sourceEncTpk), lmk);
		logger.info("tpk : "+HexFormat.of().formatHex(tpk));
		
		final byte[] zpk = TripleDes.decryptTDES(HexFormat.of().parseHex(targetEncZpk), lmk);
		logger.info("zpk : "+HexFormat.of().formatHex(zpk));
		
		
		final byte[] decryptedPinblock = TripleDes.decryptTDES(HexFormat.of().parseHex(pinblock), tpk);
		logger.info("decryptedPinblock : "+HexFormat.of().formatHex(decryptedPinblock));
		final byte[] encryptedPinblock = TripleDes.encryptTDES(decryptedPinblock, zpk);
		logger.info("encryptedPinblock : "+HexFormat.of().formatHex(encryptedPinblock));
		
		return command + "00" + HexFormat.of().formatHex(encryptedPinblock);
	}

}
