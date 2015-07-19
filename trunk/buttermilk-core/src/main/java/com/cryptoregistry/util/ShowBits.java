package com.cryptoregistry.util;

import java.io.UnsupportedEncodingException;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.List;

import com.cryptoregistry.util.entropy.BiEntropy;
import com.cryptoregistry.util.entropy.TresBiEntropy;

public class ShowBits {
	
	private List<Character> binaryExpansion;
	private String input;
	
	private final static String asciiList = buildPrintableASCIIList(); 
	
	public ShowBits(String input) {
		binaryExpansion = new ArrayList<Character>();
		this.input = input;
		collect();
	}
	
	public String showLongForm() {
		StringBuffer buf = new StringBuffer();
		buf.append(input);
		buf.append(" ");
		for(Character c: binaryExpansion){	
			buf.append(c.charValue());
		}
		TresBiEntropy bi = new TresBiEntropy(input, FileUtil.ARMOR.none);
		String s = bi.calc().biEntropyFormatted();
		buf.append(" ");
		buf.append(s);
		return buf.toString();
	}
	
	public final static String printableASCII() {
		return new ShowBits(asciiList).showColumnForm();
	}
	
	public String showColumnForm() {
		List<Wrapper> list = wrapUTF8Chars(input);
		StringBuffer buf = new StringBuffer();
		for(Wrapper w: list){
			buf.append(w.ch);
			buf.append(" ");
			buf.append(byteArrayBits(w.bytes));
			buf.append(" ");
			if(w.bytes.length == 1){
				buf.append(" B ");
				BiEntropy bi = new BiEntropy(w.bytes[0]);
				buf.append(bi.calc().biEntropyFormatted());
			}else{
				buf.append(" T ");
				TresBiEntropy tbi = new TresBiEntropy(w.bytes);
				buf.append(tbi.calc().biEntropyFormatted());
			}
			buf.append("\n");
		}
		return buf.toString();
	}
	
	public static final Charset UTF8 = Charset.forName("UTF-8");
	
	public static class Wrapper {
		public char ch;
		public byte [] bytes;
		public Wrapper(char ch, byte[] bytes) {
			super();
			this.ch = ch;
			this.bytes = bytes;
		}
	}
	
	private List<Wrapper> wrapUTF8Chars(String in){
		
		ArrayList<Wrapper> results = new ArrayList<Wrapper>();
		char[] inputChars = in.toCharArray();
		char [] oneChar = new char[1];
		for(int i = 0;i<inputChars.length;i++){
			char c = inputChars[i];
			oneChar[0] = c;
			ByteBuffer byteBuffer = UTF8.encode(CharBuffer.wrap(oneChar));
			byte [] bytes = new byte [byteBuffer.remaining()];
			byteBuffer.get(bytes);
			results.add(new Wrapper(c,bytes));
		}

		return results;
	}
	
	private String byteArrayBits(byte [] bytes){
		StringBuffer buf = new StringBuffer();
		for(int i = 0; i<bytes.length; i++){
			buf.append(bitsAsString(unsignedByte(bytes[i])));
		}
		return buf.toString();
	}
	
	private String bitsAsString(int b) {
		String s = Integer.toBinaryString(b);
		if(s.length() > 8) {
			throw new RuntimeException("Expecting to work with 8 bits or less: "+s.length());
		}
		if(s.length() == 8) return s;
		else if(s.length() == 7) return "0"+s;
		else if(s.length() == 6) return "00"+s;
		else if(s.length() == 5) return "000"+s;
		else if(s.length() == 4) return "0000"+s;
		else if(s.length() == 3) return "00000"+s;
		else if(s.length() == 2) return "000000"+s;
		else if(s.length() == 1) return "0000000"+s;
		else if(s.length() == 0) return "00000000";
		else return "";
	}
	
	/**
	 * Convert the byte from a 2's complement (signed byte) value into an unsigned integer value
	 */
	private void collect(){
		try {
			for(byte b: input.getBytes("UTF-8")){
				push(unsignedByte(b));
			}
		} catch (UnsupportedEncodingException e) {}
	}
	
	private int unsignedByte(byte b){
		return ((int) b) & 0xFF; 
	}
	
	/**
	 * Convert byte into a char array of ones and zeroes characters, push 
	 * on to the binaryExpansion stack
	 * 
	 * @param b
	 */
	private void push(int b){
		char [] word = bitsAsString(b).toCharArray();
		for(char ch : word){
			binaryExpansion.add(ch);
		}
	}
	
	private static final String buildPrintableASCIIList() {
		StringBuffer buf = new StringBuffer();
		for(int i = 32;i<128;i++){
			buf.append((char)i);
		}
		return buf.toString();
	}

}
