/*
 *  This file is part of Buttermilk
 *  Copyright 2011-2014 David R. Smith All Rights Reserved.
 *
 */
package com.cryptoregistry.ec;

import java.io.ByteArrayOutputStream;
import java.io.StringReader;
import java.io.StringWriter;
import java.math.BigInteger;

import org.junit.Assert;
import org.junit.Test;

import com.cryptoregistry.CryptoKeyWrapper;
import com.cryptoregistry.KeyMaterials;
import com.cryptoregistry.MapData;
import com.cryptoregistry.formats.JSONFormatter;
import com.cryptoregistry.formats.JSONReader;
import com.cryptoregistry.signature.ECDSACryptoSignature;
import com.cryptoregistry.signature.RefNotFoundException;
import com.cryptoregistry.signature.SelfContainedJSONResolver;
import com.cryptoregistry.signature.builder.ECDSASignatureBuilder;
import com.cryptoregistry.signature.builder.MapDataContentsIterator;
import com.cryptoregistry.signature.validator.SelfContainedSignatureValidator;

import x.org.bouncycastle.crypto.Digest;
import x.org.bouncycastle.crypto.digests.SHA1Digest;
import x.org.bouncycastle.crypto.digests.SHA256Digest;
import x.org.bouncycastle.crypto.digests.SHA512Digest;
import x.org.bouncycastle.math.ec.ECCurve;
import x.org.bouncycastle.math.ec.ECPoint;
import x.org.bouncycastle.util.encoders.Hex;

public class ECCryptoTest {
	
	// see http://crypto.stackexchange.com/questions/18488/ecdsa-with-sha256-and-sepc192r1-curve-impossible-or-how-to-calculate-e
	// There does appear to be an issue, SHA-256 will work in some cases but not others
	// we solve this by re-digesting the input if it is too long using SHA1
	@Test
	public void testZ() {
		for(CurveFactory.CurveName c: CurveFactory.CurveName.values()){
			testrun(c, new SHA1Digest());
			testrun(c, new SHA256Digest()); // these are re-digested internally to the Factory methods
			testrun(c, new SHA512Digest());
		}
	}
	
	private void testrun(CurveFactory.CurveName c, Digest digest){
		System.err.println("testing: "+c.name());
		String signedBy = "Chinese Eyes"; // my registration handle
		String message = "My message text...";
		
		ECKeyContents ecKeys = CryptoFactory.INSTANCE.generateKeys(c.name());
		ECDSASignatureBuilder builder = new ECDSASignatureBuilder(signedBy, ecKeys);
		MapData data = new MapData();
		data.put("Msg", message);
		data.put("Empty", "");
		data.put("Null", null);
		MapDataContentsIterator iter = new MapDataContentsIterator(data);
		while(iter.hasNext()){
			String label = iter.next();
			builder.update(label, iter.get(label));
		}
		ECDSACryptoSignature sig = builder.build();
		JSONFormatter format = new JSONFormatter(signedBy);
		format.add(ecKeys);
		format.add(data);
		format.add(sig);
		
		StringWriter writer = new StringWriter();
		format.format(writer);
		String serialized = writer.toString();
		
		JSONReader js = new JSONReader(new StringReader(serialized));
		KeyMaterials km = js.parse();
		SelfContainedSignatureValidator validator = new SelfContainedSignatureValidator(km);
		Assert.assertTrue(validator.validate());
	}
	
	
	

	/**
	 * Test custom curve construction
	 * 
	 */
	@Test
	public void test0() {

		// use params for P-256, imagine these are for a new unnamed curve in the prime field
		// prime field
		// p = 2^224 (2^32 - 1) + 2^192 + 2^96 - 1
		BigInteger p = fromHex("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF");
		BigInteger a = fromHex("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC");
		BigInteger b = fromHex("5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B");
		byte[] S = Hex.decode("C49D360886E704936A6678E1139D26B7819F7E90");
		BigInteger n = fromHex("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551");
		BigInteger h = BigInteger.valueOf(1);

		ECCurve curve0 = new ECCurve.Fp(p, a, b);
		ECPoint G0 = curve0
				.decodePoint(Hex
						.decode("04"
								+ "6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296"
								+ "4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5"));

		// use a custom curve as input - in this case, we just use a known curve
		// definition (P-256)
		ECCustomParameters ucst = new ECFPCustomParameters(p, a, b, S, n, h, G0);
		ECKeyContents contents = CryptoFactory.INSTANCE
				.generateCustomKeys(ucst);

		Assert.assertNotNull(contents);
		JSONFormatter format = new JSONFormatter("Chinese Knees");
		format.add(contents);
		StringWriter writer = new StringWriter();
		format.format(writer);
		String json = writer.toString();
		StringReader reader = new StringReader(writer.toString());
		JSONReader jreader = new JSONReader(reader);
		KeyMaterials km = jreader.parse();
		CryptoKeyWrapper wrapper = km.keys().get(0);
		Assert.assertNotNull(wrapper);
		ECKeyContents contents1 = (ECKeyContents) wrapper.getKeyContents();
		
		Assert.assertNotNull(contents1);
		
		format = new JSONFormatter("Chinese Knees");
		format.add(contents1);
		writer = new StringWriter();
		format.format(writer);
		Assert.assertEquals(json, writer.toString());

	}

	protected static BigInteger fromHex(String hex) {
		return new BigInteger(1, Hex.decode(hex));
	}
	
	@Test
	public void test1() {
		
		String signedBy = "Chinese Eyes"; // my registration handle
		String message = "My message text...";
		
		ECKeyContents ecKeys = CryptoFactory.INSTANCE.generateKeys("P-256");
		ECDSASignatureBuilder builder = new ECDSASignatureBuilder(signedBy, ecKeys);
		MapData data = new MapData();
		data.put("Msg", message);
		MapDataContentsIterator iter = new MapDataContentsIterator(data);
		while(iter.hasNext()){
			String label = iter.next();
			builder.update(label, iter.get(label));
		}
		ECDSACryptoSignature sig = builder.build();
		JSONFormatter format = new JSONFormatter(signedBy);
		format.add(ecKeys);
		format.add(data);
		format.add(sig);
		StringWriter writer = new StringWriter();
		format.format(writer);
		String serialized = writer.toString();
		System.err.println(serialized);
		
		// now validate the serialized text
		
		SelfContainedJSONResolver resolver = new SelfContainedJSONResolver(serialized);
		resolver.walk();
		ByteArrayOutputStream out = new ByteArrayOutputStream();
		try {
			resolver.resolve(sig.dataRefs,out);
			byte [] msgBytes = out.toByteArray();
			SHA1Digest digest = new SHA1Digest();
			digest.update(msgBytes, 0, msgBytes.length);
			byte [] m = new byte[digest.getDigestSize()];
			digest.doFinal(m, 0);
			
			boolean ok = CryptoFactory.INSTANCE.verify(sig, ecKeys, m);
			Assert.assertTrue(ok);
		} catch (RefNotFoundException e) {
			e.printStackTrace();
		}
		
		JSONReader js = new JSONReader(new StringReader(serialized));
		KeyMaterials km = js.parse();
		
		// newer way, encapsulates the above
		SelfContainedSignatureValidator validator = new SelfContainedSignatureValidator(km);
		Assert.assertTrue(validator.validate());
	}
	
}

