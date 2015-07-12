/*
 *  This file is part of Buttermilk
 *  Copyright 2011-2014 David R. Smith All Rights Reserved.
 *
 */

package com.cryptoregistry.c2;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.StringReader;
import java.io.StringWriter;
import java.io.UnsupportedEncodingException;
import java.nio.charset.Charset;
import java.util.Arrays;
import java.util.List;

import org.junit.Test;

import x.org.bouncycastle.crypto.digests.SHA256Digest;

import com.cryptoregistry.CryptoKey;
import com.cryptoregistry.CryptoKeyWrapper;
import com.cryptoregistry.KeyMaterials;
import com.cryptoregistry.MapData;
import com.cryptoregistry.c2.CryptoFactory;
import com.cryptoregistry.c2.key.AgreementPrivateKey;
import com.cryptoregistry.c2.key.C2KeyMetadata;
import com.cryptoregistry.c2.key.Curve25519KeyContents;
import com.cryptoregistry.c2.key.Curve25519KeyForPublication;
import com.cryptoregistry.c2.key.PublicKey;
import com.cryptoregistry.c2.key.SecretKey;
import com.cryptoregistry.c2.key.SigningPrivateKey;
import com.cryptoregistry.formats.EncodingHint;
import com.cryptoregistry.formats.JSONFormatter;
import com.cryptoregistry.formats.JSONReader;
import com.cryptoregistry.formats.KeyFormat;
import com.cryptoregistry.formats.Mode;
import com.cryptoregistry.pbe.PBEAlg;
import com.cryptoregistry.signature.C2CryptoSignature;
import com.cryptoregistry.signature.CryptoSignature;
import com.cryptoregistry.signature.RefNotFoundException;
import com.cryptoregistry.signature.SelfContainedJSONResolver;
import com.cryptoregistry.signature.builder.C2SignatureBuilder;
import com.cryptoregistry.signature.builder.MapDataContentsIterator;
import com.cryptoregistry.util.TimeUtil;
import com.cryptoregistry.util.XORUtil;

import junit.framework.Assert;

public class Curve25519Test {
	
	// dummy keys with controlled values
	private static final byte[] P={
		3,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
	};
	private static final byte[] s={
		5,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
	};
	private static final byte[] k={
		9,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
	};
	
	private static final String uuidVal = "2eb1cdc9-65fe-4f3e-b029-5fd29d035ae8";
	private static final String date = "2015-07-11T07:08:27+0000";
	private static final EncodingHint hint = EncodingHint.Base64url;
	private static final char [] passwordChars = {'p','a','s','s'}; 
	
	@Test
	public void testKeyFormats() {
		
		KeyFormat format = KeyFormat.unsecured();
		
		C2KeyMetadata meta = new C2KeyMetadata(uuidVal, TimeUtil.getISO8601FormatDate(date), format);
		Curve25519KeyContents contents0 = new Curve25519KeyContents(
				meta,
				new PublicKey(P), 
				new SigningPrivateKey(s), 
				new AgreementPrivateKey(k)
		);
		
		// should be equal
		Curve25519KeyContents contentsClone = contents0.clone();
		Assert.assertEquals(contents0,contentsClone);
		
		// for publication semantics
		Curve25519KeyForPublication pub = contents0.copyForPublication();
		Assert.assertEquals(contents0.metadata.getHandle(),pub.metadata.getHandle());
		Assert.assertEquals(contents0.metadata.createdOn,pub.metadata.createdOn);
		Assert.assertEquals(Mode.REQUEST_FOR_PUBLICATION, pub.metadata.format.mode);
		Assert.assertEquals(null, pub.metadata.format.pbeParams);
		Assert.assertEquals(contents0.publicKey,pub.publicKey);
	}

	@Test
	public void test0() {
		
		// prove secret key agreement alg works; also that transform through formatting does not alter keys
		Curve25519KeyContents keys0 = CryptoFactory.INSTANCE.generateKeys();
		Curve25519KeyContents keys1 = CryptoFactory.INSTANCE.generateKeys();
		SecretKey s0 = CryptoFactory.INSTANCE.keyAgreement(keys1.publicKey, keys0.agreementPrivateKey);
		SecretKey s1 = CryptoFactory.INSTANCE.keyAgreement(keys0.publicKey, keys1.agreementPrivateKey);
		Assert.assertTrue(test_equal(s0.getBytes(),s1.getBytes()));
		System.err.println("keys0 public key="+Arrays.toString(keys0.publicKey.getBytes()));
		System.err.println("keys1 public key="+Arrays.toString(keys1.publicKey.getBytes()));
		System.err.println("keys0 agreement private key="+Arrays.toString(keys0.agreementPrivateKey.getBytes()));
		System.err.println("keys1 agreement private key="+Arrays.toString(keys1.agreementPrivateKey.getBytes()));
		System.err.println("keys0 signing private key="+Arrays.toString(keys0.signingPrivateKey.getBytes()));
		System.err.println("keys1 signing private key="+Arrays.toString(keys1.signingPrivateKey.getBytes()));
		
		JSONFormatter format = new JSONFormatter("Chinese Eyes");
		format.add(keys0).add(keys1);
		StringWriter writer = new StringWriter();
		format.format(writer);
		System.err.println(writer.toString());
		
		JSONReader reader = new JSONReader(new StringReader(writer.toString()));
		KeyMaterials km = reader.parse();
		List<CryptoKeyWrapper> list = km.keys();
		Curve25519KeyContents _keys0 = (Curve25519KeyContents) list.get(0).getKeyContents();
		Curve25519KeyContents _keys1 = (Curve25519KeyContents) list.get(1).getKeyContents();
		
		Assert.assertNotNull(_keys0);
		Assert.assertNotNull(_keys1);
		
		// still works after formatting 
		s0 = CryptoFactory.INSTANCE.keyAgreement(_keys1.publicKey, _keys0.agreementPrivateKey);
		s1 = CryptoFactory.INSTANCE.keyAgreement(_keys0.publicKey, _keys1.agreementPrivateKey);
		
		System.err.println("_keys0 public key="+Arrays.toString(_keys0.publicKey.getBytes()));
		System.err.println("_keys1 public key="+Arrays.toString(_keys1.publicKey.getBytes()));
		System.err.println("_keys0 private key="+Arrays.toString(_keys0.agreementPrivateKey.getBytes()));
		System.err.println("_keys1 private key="+Arrays.toString(_keys1.agreementPrivateKey.getBytes()));
		System.err.println("_keys0 signing private key="+Arrays.toString(_keys0.signingPrivateKey.getBytes()));
		System.err.println("_keys1 signing private key="+Arrays.toString(_keys1.signingPrivateKey.getBytes()));
		
		Assert.assertTrue(test_equal(s0.getBytes(),s1.getBytes()));
		
	}
	
	private boolean test_equal(byte[] a, byte[] b) {
		int i;
		for (i = 0; i < 32; i++) {
			if (a[i] != b[i]) {
				return false;
			}
		}
		return true;
	}
	
	
	/* deterministic EC-KCDSA
	 *
	 *    s is the private key for signing
	 *    P is the corresponding public key
	 *    Z is the context data (signer public key or certificate, etc)
	 *
	 * signing:
	 *
	 *    m = hash(Z, message)
	 *    x = hash(m, s)
	 *    keygen25519(Y, NULL, x);
	 *    r = hash(Y);
	 *    h = m XOR r
	 *    sign25519(v, h, x, s);
	 *
	 *    output (v,r) as the signature
	 *
	 * verification:
	 *
	 *    m = hash(Z, message);
	 *    h = m XOR r
	 *    verify25519(Y, v, h, P)
	 *
	 *    confirm  r == hash(Y)
	 *
	 * It would seem to me that it would be simpler to have the signer directly do 
	 * h = hash(m, Y) and send that to the recipient instead of r, who can verify 
	 * the signature by checking h == hash(m, Y).  If there are any problems with 
	 * such a scheme, please let me know.
	 *
	 * Also, EC-KCDSA (like most DS algorithms) picks x random, which is a waste of 
	 * perfectly good entropy, but does allow Y to be calculated in advance of (or 
	 * parallel to) hashing the message.
	 */
	
	/* Signature generation primitive, calculates (x-h)s mod q
	 *   v  [out] signature value
	 *   h  [in]  signature hash (of message, signature pub key, and context data)
	 *   x  [in]  signature private key
	 *   s  [in]  private key for signing
	 * returns true on success, false on failure (use different x or h)
	 */
	
	/* Signature verification primitive, calculates Y = vP + hG
	 *   Y  [out] signature public key
	 *   v  [in]  signature value
	 *   h  [in]  signature hash
	 *   P  [in]  public key
	 */
	
	@Test
	public void test1() {
		Curve25519 c2 = new Curve25519();
		
		String message = "My message text...";
		byte[]msgBytes = message.getBytes(Charset.forName("UTF-8"));
		
		Curve25519KeyContents c2Keys = CryptoFactory.INSTANCE.generateKeys();
		SigningPrivateKey spk = c2Keys.signingPrivateKey;
		PublicKey pKey = c2Keys.publicKey;
		
		// compute m
		SHA256Digest digest = new SHA256Digest();
		digest.update(pKey.getBytes(), 0, pKey.length());
		digest.update(msgBytes, 0, msgBytes.length);
		byte [] m = new byte[32];
		digest.doFinal(m, 0);
		
		// compute x
		digest = new SHA256Digest();
		digest.update(m, 0, m.length);
		digest.update(spk.getBytes(), 0, spk.length());
		byte [] x = new byte[32];
		digest.doFinal(x, 0);
		
		// compute Y
		// keygen25519(Y, NULL, x);
		byte [] Y = new byte[32];
		c2.keygen(Y, null, x);
		
		// compute r
		byte [] r = new byte[32];
		digest.update(Y,0,Y.length);
		digest.doFinal(r, 0);
		
		// compute h: m XOR r
		byte [] h = XORUtil.xor(m, r);
		
		// sign, v is the signature
		byte [] v = new byte[32];
		boolean ok = c2.sign(v, h, x, spk.getBytes());
		Assert.assertTrue(ok);
		
		// compute Y again
		byte [] Yx = new byte[32];
		c2.verify(Yx, v, h, pKey.getBytes());
		
		// get hash(Yx)
		digest.update(Yx, 0, Yx.length);
		byte [] check = new byte[32];
		digest.doFinal(check, 0);
		
		Assert.assertTrue(test_equal(r,check));
	}
	
	@Test
	public void test2() {
		
		String signedBy = "Chinese Eyes"; // my registration handle
		String message = "My message text...";
		byte[]msgBytes = message.getBytes(Charset.forName("UTF-8"));
		
		
		Curve25519KeyContents c2Keys = CryptoFactory.INSTANCE.generateKeys();
		C2CryptoSignature sig = CryptoFactory.INSTANCE.sign(signedBy,c2Keys, msgBytes, new SHA256Digest());
		boolean ok = CryptoFactory.INSTANCE.verify(c2Keys, msgBytes, sig.getSignature(),new SHA256Digest());
		Assert.assertTrue(ok);
	}
	
	@Test
	public void test3() {
		
		String signedBy = "Chinese Eyes"; // my registration handle
		String message = "My message text...";
		
		Curve25519KeyContents c2Keys = CryptoFactory.INSTANCE.generateKeys();
		C2SignatureBuilder builder = new C2SignatureBuilder(signedBy, c2Keys);
		MapData data = new MapData();
		data.put("Msg", message);
		MapDataContentsIterator iter = new MapDataContentsIterator(data);
		while(iter.hasNext()){
			String label = iter.next();
			builder.update(label, iter.get(label));
		}
		C2CryptoSignature sig = builder.build();
		JSONFormatter format = new JSONFormatter(signedBy);
		format.add(c2Keys);
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
			SHA256Digest digest = new SHA256Digest();
			digest.update(msgBytes, 0, msgBytes.length);
			byte [] m = new byte[digest.getDigestSize()];
			digest.doFinal(m, 0);
			
			boolean ok = CryptoFactory.INSTANCE.verify(c2Keys, m, sig.getSignature(),new SHA256Digest());
			Assert.assertTrue(ok);
		} catch (RefNotFoundException e) {
			e.printStackTrace();
		}
	}
	
	@Test
	public void test4() {
		InputStream in = this.getClass().getResourceAsStream("/chinese-eyes.json");
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
				SHA256Digest digest = new SHA256Digest();
				digest.update(msgBytes, 0, msgBytes.length);
				byte [] m = new byte[digest.getDigestSize()];
				digest.doFinal(m, 0);
				
				C2CryptoSignature _sig = (C2CryptoSignature) sig;
				boolean ok = CryptoFactory.INSTANCE.verify((Curve25519KeyForPublication)key, m, _sig.signature,new SHA256Digest());
				Assert.assertTrue(ok);
			
			} catch (Exception e) {
				e.printStackTrace();
			}
		}finally{
			if(reader != null)
				try {
					reader.close();
				} catch (IOException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
		}
	}
	
}
