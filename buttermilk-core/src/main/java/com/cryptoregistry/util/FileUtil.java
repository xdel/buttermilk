/*
 *  This file is part of Buttermilk(TM) 
 *  Copyright 2013 David R. Smith for cryptoregistry.com
 *
 */
package com.cryptoregistry.util;

import java.io.File;
import java.io.IOException;
import java.io.StringWriter;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;

import net.iharder.Base64;
import x.org.bouncycastle.util.encoders.Hex;

/**
 * The Java 7 idioms
 * 
 */
public class FileUtil {

	public static String readFile(String path) {
		try {
			return readFile(path, StandardCharsets.UTF_8);
		} catch (IOException e) {
			throw new RuntimeException(e);
		}
	}
	
	public static void writeFile(String fileName, String data){
		try {
			File file = new File(fileName);
			String path = file.getCanonicalPath();
			Files.write(Paths.get(path), 
					data.getBytes(StandardCharsets.UTF_8));
			System.out.println("Wrote: "+path);
		} catch (IOException e) {
			throw new RuntimeException(e);
		}
	}
	
	public static void writeFile(String fileName, byte [] data){
		try {
			File file = new File(fileName);
			String path = file.getCanonicalPath();
			Files.write(Paths.get(path), data);
			System.out.println("Wrote: "+path);
		} catch (IOException e) {
			throw new RuntimeException(e);
		}
	}

	// http://stackoverflow.com/questions/326390/how-to-create-a-java-string-from-the-contents-of-a-file/326440#326440
	// for smaller files, obviously
	public static String readFile(String path, Charset encoding)
			throws IOException {
		byte[] encoded = Files.readAllBytes(Paths.get(path));
		return encoding.decode(ByteBuffer.wrap(encoded)).toString();
	}
	
	/**
	 * For smaller files, obviously
	 * @param path
	 * @param armor
	 * @return
	 * @throws IOException
	 */
	public static byte[] readFile(String path, ARMOR armor)
			throws IOException {
		byte[] bytes = Files.readAllBytes(Paths.get(path));
		if(armor == null || armor == ARMOR.none){
			return bytes;
		}else{
			switch(armor){
				case hex:
				case base16:{
					return Hex.decode(bytes);
				}
				case base64:{
					return Base64.decode(bytes);
				}
				case base64url:{
					return Base64.decode(bytes, 0, bytes.length, Base64.URL_SAFE);
				}
				default: throw new RuntimeException("Unknown option");
			}
		}
	}

	/**
	 * Read sequentially all the paths and return as one logical continuation.
	 * Note this is intended for relatively small files.
	 * 
	 * @param encoding
	 * @param paths
	 * @return
	 * @throws IOException
	 */
	public static String readFiles(Charset encoding, String... paths)
			throws IOException {

		StringWriter writer = new StringWriter();
		for (String path : paths) {
			byte[] encoded = Files.readAllBytes(Paths.get(path));
			writer.write(encoding.decode(ByteBuffer.wrap(encoded)).toString());
		}

		return writer.toString();
	}
	
	public enum ARMOR {
		none,base64,base64url,base16,hex;
	}

}
