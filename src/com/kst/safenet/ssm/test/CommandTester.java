package com.kst.safenet.ssm.test;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.util.HexFormat;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class CommandTester {

	private static final Logger logger = LoggerFactory.getLogger(CommandTester.class);
	private static final byte[] HEADER = HexFormat.of().parseHex("01010006");
	
	
	public static void main(String[] args) throws IOException {
		//System.out.println(send("EE0400001113FF49E645D0AECC1D6E488BB9CCACCC790200"));
		//System.out.println(send("ee060200efe7ad4dc949099a111146999c7ce9d857f1e7039f274b87b92501559100009565011111bcd534dfb9ba5146773f0e970925ed0c"));
		//System.out.println(send("EE02000005081002003201001092374B4E894B4F54BC2F87072A2A998F"));
		//System.out.println(send("EE0701000004000000000000000011112A439EB68D1A3D98B6C2983358A890562C1100F230A741A8E09A0000000000000000014768171027063083000000000000261500497516230109130553"));
		System.out.println(send("EE07020000000000000000000011112A439EB68D1A3D98B6C2983358A8905604EC6142E72E1110F230A2010EC18200000000001400000147681710270630830000000000002615004975162301091305530000"));
	}
	
	
	public static final String send(final String command) throws IOException {
		try(Socket socket = new Socket("127.0.0.1", 4002);
				OutputStream os = socket.getOutputStream();
				InputStream in = socket.getInputStream()) {
				socket.setSoTimeout(30000);
				ByteArrayOutputStream baos = new ByteArrayOutputStream();
				baos.write(HEADER);
				baos.write((command.length()/2) / 256);
				baos.write((command.length()/2) % 256);
				baos.write(HexFormat.of().parseHex(command));
				final byte[] request = baos.toByteArray();
				logger.trace("command", command);
				os.write(request);
				os.flush();
				final byte[] responseheader = new byte[4];
				for (int i = 0; i < responseheader.length; i++) {
					responseheader[i] = (byte) in.read();
				}
				final int b1 = in.read() & 0xFF;
				final int b2 = in.read() & 0xFF;
				final int length = b1 * 256 + b2;
				final byte[] response = new byte[length];
				in.read(response);
				logger.trace("response", HexFormat.of().formatHex(response));
				return HexFormat.of().formatHex(response);
			} catch (Exception e) {e.printStackTrace();}
			return null;
		}
}
