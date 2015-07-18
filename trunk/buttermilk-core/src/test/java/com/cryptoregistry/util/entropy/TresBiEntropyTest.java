package com.cryptoregistry.util.entropy;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import net.iharder.Base64;

import org.junit.Assert;
import org.junit.Test;

import x.org.bouncycastle.util.encoders.Hex;

import com.cryptoregistry.rsa.CryptoFactory;
import com.cryptoregistry.rsa.RSAKeyContents;
import com.cryptoregistry.util.FileUtil;
import com.cryptoregistry.util.entropy.TresBiEntropy.Result;

public class TresBiEntropyTest {

	@Test
	public void test0() {
		
		byte [] bytes = {'\0','\0','\0','\0','\0','\0','\0','\0'};
		String input = Base64.encodeBytes(bytes);
		TresBiEntropy t = new TresBiEntropy(input, FileUtil.ARMOR.base64);
		Assert.assertTrue(t.calc().biEntropy == 0);
		
		SecureRandom rand = null;
		try {
			rand = SecureRandom.getInstanceStrong();
		} catch (NoSuchAlgorithmException e) {}
		
		byte [] randBytes = new byte [32];
		rand.nextBytes(randBytes);
		
		input = new String(Hex.encode(randBytes));
		t = new TresBiEntropy(input, FileUtil.ARMOR.hex);
		Result res = t.calc();
		System.out.println(res);
		Assert.assertTrue(res.biEntropy > 0.9);
		System.out.println(res.toJSON());
		
		RSAKeyContents contents = CryptoFactory.INSTANCE.generateKeys();
		System.err.println("key bit count:"+contents.p.bitCount());
		byte [] bigIntBytes = contents.p.toByteArray();
		
		input = new String(Hex.encode(bigIntBytes));
		t = new TresBiEntropy(input, FileUtil.ARMOR.hex);
		res = t.calc();
		System.out.println(res);
		Assert.assertTrue(res.biEntropy > 0.9);
		System.out.println(res.toJSON());
		
	}
}
