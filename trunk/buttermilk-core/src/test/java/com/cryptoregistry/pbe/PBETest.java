/*
 *  This file is part of Buttermilk
 *  Copyright 2011-2014 David R. Smith All Rights Reserved.
 *
 */
package com.cryptoregistry.pbe;


import java.security.SecureRandom;

import junit.framework.Assert;

import org.junit.Test;

import x.org.bouncycastle.crypto.generators.SCrypt;
import x.org.bouncycastle.util.Arrays;

import com.cryptoregistry.passwords.NewPassword;
import com.cryptoregistry.passwords.Password;
import com.cryptoregistry.passwords.SensitiveBytes;

public class PBETest {

	@Test
	public void test0() throws Exception {
		
		byte [] input = "input test is a lot of tiny bytes".getBytes("UTF-8");
		
		char[]p= {'p','a','s','s','w','o','r','d'};
		Password pass0 = new NewPassword(p);
		byte [] salt0 = {'s', 'a', 'l', 't'};
		SensitiveBytes sb = new SensitiveBytes(salt0);
		int iterations = 100;
		
		PBEParams params = new PBEParams(PBEAlg.PBKDF2);
		params.setSalt(sb);
		params.setIterations(iterations);
		params.setPassword(pass0);
		
		PBE pbe0 = new PBE(params);
		ArmoredPBKDF2Result result = (ArmoredPBKDF2Result) pbe0.encrypt(input);
		
		// now decrypt
		
		char[]q= {'p','a','s','s','w','o','r','d'};
		Password pass1 = new NewPassword(q);
		params = new PBEParams(PBEAlg.PBKDF2);
		SensitiveBytes sb1 = new SensitiveBytes(result.getSaltBytes());
		params.setSalt(sb1);
		params.setIterations(result.iterations);
		params.setPassword(pass1);
		
		PBE pbe1 = new PBE(params);
		byte [] output = pbe1.decrypt(result.getResultBytes());
		
		Assert.assertTrue(Arrays.areEqual(input, output));
	}
	
	/**
	 * Test scrypt
	 * 
	 * @throws Exception
	 */
	
	@Test
	public void test1() throws Exception {
		
		byte [] input = "input test is a lot of tiny bytes".getBytes("UTF-8");
		
		SecureRandom rand = new SecureRandom();
		byte [] iv = new byte[16];
		rand.nextBytes(iv);
		
		char[]p= {'p','a','s','s','w','o','r','d'};
		Password pass0 = new NewPassword(p);
		byte [] salt0 = {'s', 'a', 'l', 't'};
		SensitiveBytes sb = new SensitiveBytes(salt0);
		
		// there is also a factory for this
		PBEParams params = new PBEParams(PBEAlg.SCRYPT);
		params.setPassword(pass0);
		params.setSalt(sb);
		params.setIv(new SensitiveBytes(iv));
		
		PBE pbe0 = new PBE(params);
		ArmoredScryptResult result = (ArmoredScryptResult) pbe0.encrypt(input);
		
		// now decrypt
		
		char[]q= {'p','a','s','s','w','o','r','d'};
		Password pass1 = new NewPassword(q);
		params = new PBEParams(PBEAlg.SCRYPT);
		SensitiveBytes sb1 = new SensitiveBytes(result.getSaltBytes());
		params.setPassword(pass1);
		params.setSalt(sb1);
		params.setIv(new SensitiveBytes(result.getIVBytes()));
		
		Assert.assertTrue(Arrays.areEqual(iv, result.getIVBytes()));
		Assert.assertTrue(Arrays.areEqual(sb.getData(), result.getSaltBytes()));
		
		PBE pbe1 = new PBE(params);
		byte [] output = pbe1.decrypt(result.getResultBytes());
		
		Assert.assertTrue(Arrays.areEqual(input, output));
	}
	
	
	
	
	/** Test the scrypt implementation algorithm from BC using one of the published test vectors
	 * 
	 * @param r the block size parameter.
	 * @param N the CPU/Memory cost parameter.
	 * @param p the parallelization parameter.
	 * @param dkLen the desired length for derived keys, in bytes.
	 * */
	
	@Test
	public void testVector2() {
		byte[]P= {'p','a','s','s','w','o','r','d'};
		byte[]S= {'N','a','C','l'};
		int N = 1024;
		int r = 8;
		int p = 16;
		int dkLen = 64;
		byte [] key = SCrypt.generate(P, S, N, r, p, dkLen);
		String res = bytesToHex(key); 
		
		String expected ="fdbabe1c9d3472007856e7190d01e9fe7c6ad7cbc8237830e77376634b3731622eaf30d92e22a3886ff109279d9830dac727afb94a83ee6d8360cbdfa2cc0640";
		Assert.assertTrue(res.equals(expected));
	}
	
	// http://stackoverflow.com/questions/9655181/how-to-convert-a-byte-array-to-a-hex-string-in-java
	// but changed to be lower case
	final protected static char[] hexArray = "0123456789abcdef".toCharArray();
	public static String bytesToHex(byte[] bytes) {
	    char[] hexChars = new char[bytes.length * 2];
	    for ( int j = 0; j < bytes.length; j++ ) {
	        int v = bytes[j] & 0xFF;
	        hexChars[j * 2] = hexArray[v >>> 4];
	        hexChars[j * 2 + 1] = hexArray[v & 0x0F];
	    }
	    return new String(hexChars);
	}
	
	// Test vectors
	
/**
	 
scrypt(“”, “”, 16, 1, 1, 64) =
77 d6 57 62 38 65 7b 20 3b 19 ca 42 c1 8a 04 97
f1 6b 48 44 e3 07 4a e8 df df fa 3f ed e2 14 42
fc d0 06 9d ed 09 48 f8 32 6a 75 3a 0f c8 1f 17
e8 d3 e0 fb 2e 0d 36 28 cf 35 e2 0c 38 d1 89 06

scrypt(“password”, “NaCl”, 1024, 8, 16, 64) =
fd ba be 1c 9d 34 72 00 78 56 e7 19 0d 01 e9 fe
7c 6a d7 cb c8 23 78 30 e7 73 76 63 4b 37 31 62
2e af 30 d9 2e 22 a3 88 6f f1 09 27 9d 98 30 da
c7 27 af b9 4a 83 ee 6d 83 60 cb df a2 cc 06 40

scrypt(“pleaseletmein”, “SodiumChloride”, 16384, 8, 1, 64) =
70 23 bd cb 3a fd 73 48 46 1c 06 cd 81 fd 38 eb
fd a8 fb ba 90 4f 8e 3e a9 b5 43 f6 54 5d a1 f2
d5 43 29 55 61 3f 0f cf 62 d4 97 05 24 2a 9a f9
e6 1e 85 dc 0d 65 1e 40 df cf 01 7b 45 57 58 87

scrypt(“pleaseletmein”, “SodiumChloride”, 1048576, 8, 1, 64) =
21 01 cb 9b 6a 51 1a ae ad db be 09 cf 70 f8 81
ec 56 8d 57 4a 2f fd 4d ab e5 ee 98 20 ad aa 47
8e 56 fd 8f 4b a5 d0 9f fa 1c 6d 92 7c 40 f4 c3
37 30 40 49 e8 a9 52 fb cb f4 5c 6f a7 7a 41 a4
*/
	

}
