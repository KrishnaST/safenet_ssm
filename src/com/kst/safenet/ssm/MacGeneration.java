package com.kst.safenet.ssm;

import java.util.HexFormat;

import org.bouncycastle.crypto.engines.DESEngine;
import org.bouncycastle.crypto.macs.ISO9797Alg3Mac;
import org.bouncycastle.crypto.paddings.ZeroBytePadding;
import org.bouncycastle.crypto.params.DESedeParameters;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.Arrays;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.kst.safenet.ssm.util.TripleDes;

public class MacGeneration implements Command {

	private static final Logger logger = LoggerFactory.getLogger(CommandProcessor.class);
	private static final byte[] lmk = HexFormat.of().parseHex(Application.properties.getProperty("lmk"));
	
	//EE0701 00 00 04 0000000000000000 11110DB37828C385C9A2A2E917582C2DF095 2C 1100F230A741A8E09A0000000000000000014768171027063083000000000000261500497516230109130553
	//EE0701 00 04 E0ADEAA2
	@Override
	public final String execute(String request) {
		final String command = request.substring(0,6);
		logger.info("command : "+command);
		final int outLen = Integer.parseInt(request.substring(10,12));
		logger.info("outLen : "+outLen);
		final String icd = request.substring(12, 28);
		logger.info("icd : "+icd);
		final String macKeyLmk = request.substring(32, 64);
		logger.info("macKeyLmk : "+macKeyLmk);
		final byte[] macKey = TripleDes.decryptTDES(HexFormat.of().parseHex(macKeyLmk), lmk);
		logger.info("macKey : "+HexFormat.of().formatHex(macKey));
		
		final int dataLen = Integer.parseInt(request.substring(64, 66), 16);
		logger.info("dataLen : "+dataLen);
		final byte[] data = HexFormat.of().parseHex(request.substring(66, 66+dataLen*2));
		logger.info("data : "+HexFormat.of().formatHex(data));
		final ISO9797Alg3Mac mac = new ISO9797Alg3Mac(new DESEngine(), outLen*8, new ZeroBytePadding());
		final DESedeParameters keyParameters = new DESedeParameters(macKey);
		final ParametersWithIV parameterIV = new ParametersWithIV(keyParameters, HexFormat.of().parseHex(icd));
	    mac.init(parameterIV);
	    mac.update(data, 0, data.length);
	    final byte[] macBytes = new byte[8];
	    mac.doFinal(macBytes, 0);
		logger.info("encryptedPinblock : "+HexFormat.of().formatHex(macBytes));
		return command + "0004" + HexFormat.of().formatHex(Arrays.copyOf(macBytes, 4));
	}

}
