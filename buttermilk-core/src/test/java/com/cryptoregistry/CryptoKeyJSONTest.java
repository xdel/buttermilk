package com.cryptoregistry;

import org.junit.Assert;
import org.junit.Test;

import com.cryptoregistry.c2.key.Curve25519KeyContents;
import com.cryptoregistry.ntru.NTRUKeyContents;

public class CryptoKeyJSONTest {

	@Test
	public void test0() {
		
		Curve25519KeyContents keys0 = com.cryptoregistry.c2.CryptoFactory.INSTANCE.generateKeys();
		String k0 = keys0.formatJSON();
		System.err.println(k0);
		Assert.assertNotNull(k0);
		
		NTRUKeyContents keys1 = com.cryptoregistry.ntru.CryptoFactory.INSTANCE.generateKeys();
		String k1 = keys1.formatJSON();
		System.err.println(k1);
		Assert.assertNotNull(k1);
		
		// TODO add the rest
		
	}

}
