package com.cryptoregistry.rsa;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.StringWriter;
import java.io.UnsupportedEncodingException;
import java.nio.charset.Charset;

import junit.framework.Assert;

import org.junit.Test;

import x.org.bouncycastle.crypto.Digest;
import x.org.bouncycastle.crypto.digests.SHA256Digest;
import x.org.bouncycastle.util.Arrays;

import com.cryptoregistry.CryptoKey;
import com.cryptoregistry.KeyMaterials;
import com.cryptoregistry.MapData;
import com.cryptoregistry.formats.JSONFormatter;
import com.cryptoregistry.formats.JSONReader;
import com.cryptoregistry.signature.CryptoSignature;
import com.cryptoregistry.signature.RSACryptoSignature;
import com.cryptoregistry.signature.RefNotFoundException;
import com.cryptoregistry.signature.SelfContainedJSONResolver;
import com.cryptoregistry.signature.builder.MapDataContentsIterator;
import com.cryptoregistry.signature.builder.RSASignatureBuilder;

public class RSATest {

	
	@Test
	public void test2() throws UnsupportedEncodingException {
		byte [] in = "Test message".getBytes("UTF-8");
		RSAKeyContents contents = CryptoFactory.INSTANCE.generateKeys();
		// test all the different RSA padding available
		for(RSAEngineFactory.Padding pad: RSAEngineFactory.Padding.values()){
			byte [] encrypted = CryptoFactory.INSTANCE.encrypt((RSAKeyForPublication)contents, pad, in);
			byte [] plain = CryptoFactory.INSTANCE.decrypt(contents, pad, encrypted);
			Assert.assertTrue(Arrays.areEqual(in, plain));
		}
	}
	
	@Test
	public void test3() throws UnsupportedEncodingException {
		
		RSAKeyContents contents = CryptoFactory.INSTANCE.generateKeys();
		
		byte [] msgBytes = "this is a test message".getBytes(Charset.forName("UTF-8"));
		SHA256Digest digest = new SHA256Digest();
		digest.update(msgBytes, 0, msgBytes.length);
		byte [] msgHashBytes = new byte[digest.getByteLength()];
		digest.doFinal(msgHashBytes, 0);
		
		RSACryptoSignature sig = CryptoFactory.INSTANCE.sign("Chinese Eyes", contents, digest.getAlgorithmName(), msgHashBytes);
		boolean ok = CryptoFactory.INSTANCE.verify(sig, contents, msgHashBytes);
		Assert.assertTrue(ok);
		
	}
	
	@Test
	public void test4() {
		
		String signedBy = "Chinese Eyes"; // my registration handle
		String message = "My message text...";
		
		RSAKeyContents rKeys = CryptoFactory.INSTANCE.generateKeys();
		RSASignatureBuilder builder = new RSASignatureBuilder(signedBy,rKeys);
		MapData data = new MapData();
		data.put("Msg", message);
		MapDataContentsIterator iter = new MapDataContentsIterator(data);
		while(iter.hasNext()){
			String label = iter.next();
			builder.update(label, iter.get(label));
		}
		RSACryptoSignature sig = builder.build();
		JSONFormatter format = new JSONFormatter(signedBy);
		format.add(rKeys);
		format.add(data);
		format.add(sig);
		StringWriter writer = new StringWriter();
		format.format(writer);
		String serialized = writer.toString();
		
		// now validate the serialized text
		
		SelfContainedJSONResolver resolver = new SelfContainedJSONResolver(serialized);
		resolver.walk();
		ByteArrayOutputStream out = new ByteArrayOutputStream();
		try {
			resolver.resolve(sig.dataRefs,out);
			byte [] msgBytes = out.toByteArray();
			Digest digest = sig.getDigestInstance();
			digest.update(msgBytes, 0, msgBytes.length);
			byte [] m = new byte[digest.getDigestSize()];
			digest.doFinal(m, 0);
			
			boolean ok = CryptoFactory.INSTANCE.verify(sig, rKeys, m);
			Assert.assertTrue(ok);
		} catch (RefNotFoundException e) {
			e.printStackTrace();
		}
	}
	
	@Test
	public void test5() {
		InputStream in = this.getClass().getResourceAsStream("/chinese-knees.json");
		Assert.assertNotNull(in);
		InputStreamReader reader = null;
		try {
			try {
				reader = new InputStreamReader(in, "UTF-8");
			} catch (UnsupportedEncodingException e1) {}
			JSONReader js = new JSONReader(reader);
			KeyMaterials km = js.parse();
			SelfContainedJSONResolver resolver = new SelfContainedJSONResolver(km.baseMap());
			resolver.walk();
			ByteArrayOutputStream out = new ByteArrayOutputStream();
			try {
				CryptoSignature sig = km.signatures().get(0);
				CryptoKey key = km.keys().get(0).getKeyContents();
				resolver.resolve(sig.dataRefs,out);
				byte [] msgBytes = out.toByteArray();
				Digest digest = sig.getDigestInstance();
				digest.update(msgBytes, 0, msgBytes.length);
				byte [] m = new byte[digest.getDigestSize()];
				digest.doFinal(m, 0);
				
				RSACryptoSignature _sig = (RSACryptoSignature) sig;
				boolean ok = CryptoFactory.INSTANCE.verify(_sig, (RSAKeyForPublication)key, m);
				Assert.assertTrue(ok);
			
			} catch (Exception e) {
				e.printStackTrace();
			}
		}finally{
			if(reader != null)
				try {
					reader.close();
				} catch (IOException e) {
					e.printStackTrace();
				}
		}
	}

}
