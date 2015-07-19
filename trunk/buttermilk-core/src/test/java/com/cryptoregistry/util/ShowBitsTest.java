package com.cryptoregistry.util;

import java.nio.charset.Charset;

import org.junit.Test;

public class ShowBitsTest {
	
	public static final Charset UTF8 = Charset.forName("UTF-8");

	@Test
	public void test0() {
		ShowBits bits = new ShowBits("password1");
		System.err.println(bits.showColumnForm());
		System.err.println(bits.showLongForm());
		
		System.err.println("");
		
		bits = new ShowBits("weather7");
		System.err.println(bits.showColumnForm());
		System.err.println(bits.showLongForm());
		
		System.err.println("");
	
		System.err.println(ShowBits.printableASCII());
		
	}
	@Test
	public void testUTF8() {
		
		// assume setup in your environment is UTF-8 ready
		ShowBits bits =  new ShowBits("特色条目");
		System.err.println(bits.showColumnForm());
		System.err.println(bits.showLongForm());
		
	}

}
