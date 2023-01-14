package com.kst.safenet.ssm;

import java.io.FileReader;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.Properties;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.logging.LogManager;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.bridge.SLF4JBridgeHandler;

//@formatter:off
public class Application {

	private static final Logger logger = LoggerFactory.getLogger(Application.class);
	private static final ExecutorService executor = Executors.newCachedThreadPool();
	public static final Properties properties = new Properties();
	
	static {
		LogManager.getLogManager().reset();
		SLF4JBridgeHandler.install();
		try {
			properties.load(new FileReader("application.properties"));
		} catch (Exception e) {logger.error("", e);}
	}
	
	public static void main(String[] args) {
		try {
			
			System.out.println("properties : " + properties);
			ServerSocket ssc = new ServerSocket(Integer.parseInt(properties.getProperty("server.port")));
			logger.info("application started.");
			while (true) {
				try {
					final Socket socket = ssc.accept();
					executor.execute(new CommandProcessor(socket));
				} catch (Exception e) {logger.error("", e);}
			}
		} catch (Exception e) {logger.error("", e);}
	}
}
