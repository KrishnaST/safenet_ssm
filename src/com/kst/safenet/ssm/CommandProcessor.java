package com.kst.safenet.ssm;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class CommandProcessor implements Runnable {
	
	private static final byte[] HEADER = HexFormat.of().parseHex("01010006");
	private static final Logger logger = LoggerFactory.getLogger(CommandProcessor.class);
	
	private static final Map<String, Command> commandMap = new HashMap<>();
	
	static {
		commandMap.put("EE0400", new GenerateTpkUnderTmk());
		commandMap.put("ee0400", commandMap.get("EE0400"));
		
		commandMap.put("EE0602", new PinblockTranslation());
		commandMap.put("ee0602", commandMap.get("EE0602"));
		
		commandMap.put("EE0200", new KeyImport());
		commandMap.put("ee0200", commandMap.get("EE0200"));
		
		commandMap.put("EE0701", new MacGeneration());
		commandMap.put("ee0701", commandMap.get("EE0701"));
		
		commandMap.put("EE0702", new MacVerification());
		commandMap.put("ee0702", commandMap.get("EE0702"));
		
	}
	
	private final Socket socket;
	
	public CommandProcessor(Socket socket) {
		this.socket = socket;
	}

	@Override
	public void run() {
		try {
			final String request = readRequest();
			final Command command = getCommand(request);
			final String response = command.execute(request);
			writeResponse(response);
		} catch (Exception e) {	logger.error("", e);}
	}

	private String readRequest() throws IOException {
		InputStream in = socket.getInputStream();
		for (int i = 0; i < 4; i++) {
			in.read();
		}
		final int b1 = in.read() & 0xFF;
		final int b2 = in.read() & 0xFF;
		final int length = b1 * 256 + b2;
		final byte[] request = new byte[length];
		in.read(request);
		logger.info("request : "+HexFormat.of().formatHex(request));
		return HexFormat.of().formatHex(request);
	}
	
	private void writeResponse(String response) throws IOException {
		final OutputStream os = socket.getOutputStream();
		final byte[] responseBytes = HexFormat.of().parseHex(response);
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		baos.write(HEADER);
		baos.write((responseBytes.length) / 256);
		baos.write((responseBytes.length) % 256);
		baos.write(responseBytes);
		final byte[] finalResponse = baos.toByteArray();
		logger.info("response : "+response);
		os.write(finalResponse);
		os.flush();
	}
	
	private Command getCommand(String request) {
		return commandMap.get(request.substring(0,6));
	}
	
	
}
