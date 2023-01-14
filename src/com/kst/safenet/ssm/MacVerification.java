package com.kst.safenet.ssm;

import java.util.HexFormat;

import org.bouncycastle.crypto.engines.DESEngine;
import org.bouncycastle.crypto.macs.ISO9797Alg3Mac;
import org.bouncycastle.crypto.paddings.ZeroBytePadding;
import org.bouncycastle.crypto.params.DESedeParameters;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.kst.safenet.ssm.util.TripleDes;

public class MacVerification implements Command {

	private static final Logger logger = LoggerFactory.getLogger(CommandProcessor.class);
	private static final byte[] lmk = HexFormat.of().parseHex(Application.properties.getProperty("lmk"));
	
	//EE0702 00 00 0000000000000000 11110DB37828C385C9A2A2E917582C2DF095 04 EC6142 E7 2E1110F230A2010EC18200000000001400000147681710270630830000000000002615004975162301091305530000
	//EE0702 00
	@Override
	public final String execute(String request) {
		final String command = request.substring(0,6);
		logger.info("command : "+command);
	
		final String icd = request.substring(10, 26);
		logger.info("icd : "+icd);
		
		final String macKeyLmk = request.substring(30, 62);
		logger.info("macKeyLmk : "+macKeyLmk);
		
		final int macLen = Integer.parseInt(request.substring(62,64));
		logger.info("macLen : "+macLen);
		
		final byte[] macData = HexFormat.of().parseHex(request.substring(64, 64+macLen*2));
		logger.info("macData : "+HexFormat.of().formatHex(macData));
		
		final int dataLen = Integer.parseInt(request.substring(64+macLen*2, 64+macLen*2+2), 16);
		logger.info("dataLen : "+dataLen);
		
		final byte[] data = HexFormat.of().parseHex(request.substring(64+macLen*2+2, (64+macLen*2+2)+dataLen*2));
		logger.info("data : "+HexFormat.of().formatHex(data));
		
		final byte[] macKey = TripleDes.decryptTDES(HexFormat.of().parseHex(macKeyLmk), lmk);
		logger.info("macKey : "+HexFormat.of().formatHex(macKey));
	
		final ISO9797Alg3Mac mac = new ISO9797Alg3Mac(new DESEngine(), macLen*8, new ZeroBytePadding());
		final DESedeParameters keyParameters = new DESedeParameters(macKey);
		final ParametersWithIV parameterIV = new ParametersWithIV(keyParameters, HexFormat.of().parseHex(icd));
	    mac.init(parameterIV);
	    mac.update(data, 0, data.length);
	    final byte[] macBytes = new byte[4];
	    mac.doFinal(macBytes, 0);
		logger.info("macBytes : "+HexFormat.of().formatHex(macBytes));
		boolean matched = HexFormat.of().formatHex(macBytes).equalsIgnoreCase(HexFormat.of().formatHex(macData)); 
		logger.info("mac matched : "+matched);
		return command +(matched ? "00" : "01");
	}

}
