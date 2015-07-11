package com.cryptoregistry.formats;

import java.nio.charset.Charset;

import junit.framework.Assert;

import org.junit.Test;

import x.org.bouncycastle.crypto.digests.SHA256Digest;

import com.cryptoregistry.c2.CryptoFactory;
import com.cryptoregistry.c2.key.Curve25519KeyContents;
import com.cryptoregistry.signature.C2CryptoSignature;

public class SignatureFormatterTest {

	@Test
	public void test() {
		String signedBy = "Chinese Eyes"; // my registration handle
		String message = "My message text...";
		byte[] msgBytes = message.getBytes(Charset.forName("UTF-8"));

		Curve25519KeyContents c2Keys = CryptoFactory.INSTANCE.generateKeys();
		C2CryptoSignature sig = CryptoFactory.INSTANCE.sign(signedBy, c2Keys, msgBytes,new SHA256Digest());
		String desc = new SignatureFormatter(sig).format();
		System.err.println(desc);
		boolean ok = CryptoFactory.INSTANCE.verify(c2Keys, msgBytes, sig.getSignature(),new SHA256Digest());
		Assert.assertTrue(ok);

	}

}
