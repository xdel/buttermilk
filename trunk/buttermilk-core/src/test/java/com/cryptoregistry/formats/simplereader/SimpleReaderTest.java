package com.cryptoregistry.formats.simplereader;

import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.StringReader;
import java.io.StringWriter;

import junit.framework.Assert;

import org.junit.Test;

import com.cryptoregistry.c2.CryptoFactory;
import com.cryptoregistry.c2.key.C2KeyMetadata;
import com.cryptoregistry.c2.key.Curve25519KeyContents;
import com.cryptoregistry.formats.JSONFormatter;
import com.cryptoregistry.formats.simplereader.JSONC2Reader;
import com.cryptoregistry.passwords.NewPassword;
import com.cryptoregistry.signature.CryptoSignature;

public class SimpleReaderTest {

	@Test
	public void test0() {
		char [] password = {'p','a','s','s','w','o','r','d','1'};
		
		C2KeyMetadata management = C2KeyMetadata.createSecurePBKDF2(password);
		Curve25519KeyContents key = CryptoFactory.INSTANCE.generateKeys(management);
		JSONFormatter formatter = new JSONFormatter("Chinese Knees");
		formatter.add(key);
		StringWriter writer = new StringWriter();
		formatter.format(writer,true);
		String jsonKey = writer.toString();
		StringReader sr = new StringReader(jsonKey);
		JSONC2Reader reader = new JSONC2Reader(sr,new NewPassword(password));
		Curve25519KeyContents result = (Curve25519KeyContents) reader.parse();
		
		Assert.assertEquals(key.agreementPrivateKey, result.agreementPrivateKey);
		Assert.assertEquals(key.publicKey, result.publicKey);
		Assert.assertEquals(key.signingPrivateKey, result.signingPrivateKey);
	
	}
	
	@Test
	public void test1() {
		InputStream in = Thread.currentThread().getClass().getResourceAsStream("/sig.json");
		InputStreamReader reader = new InputStreamReader(in);
		SignatureReader sr = new SignatureReader(reader);
		CryptoSignature sig = sr.read();
		Assert.assertNotNull(sig);
		
	}

}
