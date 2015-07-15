package com.cryptoregistry.formats;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.StringReader;
import java.io.StringWriter;
import java.io.UnsupportedEncodingException;
import java.nio.charset.Charset;
import java.util.Date;
import java.util.List;

import net.iharder.Base64;

import org.junit.Assert;
import org.junit.Test;

import x.org.bouncycastle.crypto.digests.SHA256Digest;
import x.org.bouncycastle.util.Arrays;

import com.cryptoregistry.CryptoContact;
import com.cryptoregistry.CryptoKey;
import com.cryptoregistry.CryptoKeyWrapper;
import com.cryptoregistry.KeyMaterials;
import com.cryptoregistry.MapData;
import com.cryptoregistry.ListData;
import com.cryptoregistry.c2.CryptoFactory;
import com.cryptoregistry.c2.key.AgreementPrivateKey;
import com.cryptoregistry.c2.key.C2KeyMetadata;
import com.cryptoregistry.c2.key.Curve25519KeyContents;
import com.cryptoregistry.c2.key.Curve25519KeyForPublication;
import com.cryptoregistry.c2.key.PublicKey;
import com.cryptoregistry.c2.key.SigningPrivateKey;
import com.cryptoregistry.passwords.NewPassword;
import com.cryptoregistry.passwords.Password;
import com.cryptoregistry.passwords.SensitiveBytes;
import com.cryptoregistry.pbe.PBEAlg;
import com.cryptoregistry.pbe.PBEParams;
import com.cryptoregistry.pbe.PBEParamsFactory;
import com.cryptoregistry.signature.C2CryptoSignature;
import com.cryptoregistry.signature.CryptoSignature;
import com.cryptoregistry.signature.SelfContainedJSONResolver;
import com.cryptoregistry.signature.builder.C2KeyContentsIterator;
import com.cryptoregistry.signature.builder.C2SignatureBuilder;
import com.cryptoregistry.signature.builder.C2SignatureCollector;
import com.cryptoregistry.signature.builder.ContactContentsIterator;
import com.cryptoregistry.signature.builder.MapDataContentsIterator;
import com.cryptoregistry.signature.builder.ListDataContentsIterator;
import com.cryptoregistry.signature.validator.SelfContainedSignatureValidator;
import com.cryptoregistry.util.MapIterator;
import com.cryptoregistry.util.TimeUtil;
import com.cryptoregistry.util.XORUtil;


public class C2FormattingTest {
	
	// dummy keys with controlled values
	private static byte[] P={
		3,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
	};
	private static byte[] s={
		5,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
	};
	private static byte[] k={
		9,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
	};
	
	
		// hypothesis good keys
	   private static String P_good = "3JVaTWVUk3wsUaBncyDfu5S4dI0aeKOVRg5PgBypIC8=";
	   private static String s_good = "LPMOH75stRqCAnEfsLLI9vUXhSyCIdL_njGH-b7zaA4=";
	   private static String k_good = "8Doemi0oJsiGNjhquM1zijJzF1FgjEb7yoSCVZOPqW8=";
	   
	   // hypothesis bad keys
	   private static String P_bad = "uqZJLi7U40p-D32Ph5IPQe0krQ2q7P-7DqMgltKwSno=";
	   private static String s_bad = "da9UYSVV2l2Z2YoWoEcQtU-AkeQedf9CIfL7_h02VQU=";
	   private static String k_bad = "cMHm13JJdavkOcQFt9c3F2O2ZfkxElQe-oZR_rbU9Xg=";
	   
	
	@Test
	public void testWrapperEnc0() {
		char [] ch0 = {'p','a','s','s'}; 
		char [] ch1 = {'p','a','s','s'}; 
		String uuidVal = "2eb1cdc9-65fe-4f3e-b029-5fd29d035ae8";
		String date = "2015-07-11T07:08:27+0000";
		EncodingHint hint = EncodingHint.Base64url;
		byte [] saltBytes = {
				's','a','l','t',
				'0','0','0','0',
				'0','0','0','0',
				'0','0','0','0',
				'0','0','0','0',
				'0','0','0','0',
				'0','0','0','0',
				'0','0','0','0',
				'0','0'};
		byte [] ivBytes = {
				'i','v','0','0',
				'0','0','0','0',
				'0','0','0','0',
				'0','0','0','0',};
		
		Password password = new NewPassword(ch0);
		SensitiveBytes salt = new SensitiveBytes(saltBytes);
		SensitiveBytes iv = new SensitiveBytes(ivBytes);
		
		PBEParams params = new PBEParams(PBEAlg.SCRYPT);
		params.setPassword(password);
		params.setSalt(salt);
		params.setIv(iv);
		params.setCpuMemoryCost_N(4);
		params.setBlockSize_r(ivBytes.length*8);
		params.setParallelization_p(32);
		params.setDesiredKeyLengthInBytes(32);
		
		KeyFormat format = new KeyFormat(hint,Mode.REQUEST_SECURE,params);
		
		C2KeyMetadata meta = new C2KeyMetadata(uuidVal, TimeUtil.getISO8601FormatDate(date), format);
		Curve25519KeyContents contents0 = new Curve25519KeyContents(
				meta,
				new PublicKey(P), 
				new SigningPrivateKey(s), 
				new AgreementPrivateKey(k)
		);
		
		JSONFormatter builder0 = new JSONFormatter("Chinese Eyes", "dave@somewhere.com");
		builder0.add(contents0);
		StringWriter writer0 = new StringWriter();
		builder0.format(writer0);
		System.err.println(writer0.toString());
		
		StringReader reader0 = new StringReader(writer0.toString());
		JSONReader jr0 = new JSONReader(reader0);
		KeyMaterials km0 = jr0.parse();
		List<CryptoKeyWrapper> wrapperList = km0.keys();
		Assert.assertTrue(wrapperList.size()==1);
		CryptoKeyWrapper keyWrapper = wrapperList.get(0);
		
		keyWrapper.unlock(new NewPassword(ch1));
		Curve25519KeyContents out = (Curve25519KeyContents) keyWrapper.getKeyContents();
		
		byte [] key0 = contents0.publicKey.getBytes();
		byte [] keyOut = out.publicKey.getBytes();
		
		for(int i = 0; i<key0.length;i++){
			byte a = key0[i];
			byte b = keyOut[i];
			if(Byte.compare(a, b) != 0){
				System.err.println("different: "+(int)a+" "+(int)b+" at index "+i);
			}
		}
		Assert.assertTrue(Arrays.areEqual(key0, keyOut));
		
		key0 = contents0.signingPrivateKey.getBytes();
		keyOut = out.signingPrivateKey.getBytes();
		
		for(int i = 0; i<key0.length;i++){
			byte a = key0[i];
			byte b = keyOut[i];
			if(Byte.compare(a, b) != 0){
				System.err.println("different: "+(int)a+" "+(int)b+" at index "+i);
			}
		}
		Assert.assertTrue(Arrays.areEqual(key0, keyOut));
		
		key0 = contents0.agreementPrivateKey.getBytes();
		keyOut = out.agreementPrivateKey.getBytes();
		
		for(int i = 0; i<key0.length;i++){
			byte a = key0[i];
			byte b = keyOut[i];
			if(Byte.compare(a, b) != 0){
				System.err.println("different: "+(int)a+" "+(int)b+" at index "+i);
			}
		}
		Assert.assertTrue(Arrays.areEqual(key0, keyOut));
		
		
		Assert.assertNotNull(out);
	}
	
	
	@Test
	public void testWrapperEnc1() throws IOException {
		char [] ch0 = {'p','a','s','s'}; 
		char [] ch1 = {'p','a','s','s'}; 
		String uuidVal = "2eb1cdc9-65fe-4f3e-b029-5fd29d035ae8";
		String date = "2015-07-11T07:08:27+0000";
		EncodingHint hint = EncodingHint.Base64url;
		byte [] saltBytes = {
				's','a','l','t',
				'0','0','0','0',
				'0','0','0','0',
				'0','0','0','0',
				'0','0','0','0',
				'0','0','0','0',
				'0','0','0','0',
				'0','0','0','0',
				'0','0'};
		byte [] ivBytes = {
				'i','v','0','0',
				'0','0','0','0',
				'0','0','0','0',
				'0','0','0','0',};
		
		Password password = new NewPassword(ch0);
		SensitiveBytes salt = new SensitiveBytes(saltBytes);
		SensitiveBytes iv = new SensitiveBytes(ivBytes);
		
		PBEParams params = new PBEParams(PBEAlg.SCRYPT);
		params.setPassword(password);
		params.setSalt(salt);
		params.setIv(iv);
		params.setCpuMemoryCost_N(4);
		params.setBlockSize_r(ivBytes.length*8);
		params.setParallelization_p(32);
		params.setDesiredKeyLengthInBytes(32);
		
		KeyFormat format = new KeyFormat(hint,Mode.REQUEST_SECURE,params);
		
		C2KeyMetadata meta = new C2KeyMetadata(uuidVal, TimeUtil.getISO8601FormatDate(date), format);
		Curve25519KeyContents contents0 = new Curve25519KeyContents(
				meta,
				new PublicKey(Base64.decode(P_good,Base64.URL_SAFE)), 
				new SigningPrivateKey(Base64.decode(s_good,Base64.URL_SAFE)), 
				new AgreementPrivateKey(Base64.decode(k_good,Base64.URL_SAFE))
		);
		
		JSONFormatter builder0 = new JSONFormatter("Chinese Eyes", "dave@somewhere.com");
		builder0.add(contents0);
		StringWriter writer0 = new StringWriter();
		builder0.format(writer0);
		System.err.println(writer0.toString());
		
		StringReader reader0 = new StringReader(writer0.toString());
		JSONReader jr0 = new JSONReader(reader0);
		KeyMaterials km0 = jr0.parse();
		List<CryptoKeyWrapper> wrapperList = km0.keys();
		Assert.assertTrue(wrapperList.size()==1);
		CryptoKeyWrapper keyWrapper = wrapperList.get(0);
		
		keyWrapper.unlock(new NewPassword(ch1));
		Curve25519KeyContents out = (Curve25519KeyContents) keyWrapper.getKeyContents();
		
		byte [] key0 = contents0.publicKey.getBytes();
		byte [] keyOut = out.publicKey.getBytes();
		
		for(int i = 0; i<key0.length;i++){
			byte a = key0[i];
			byte b = keyOut[i];
			if(Byte.compare(a, b) != 0){
				System.err.println("different: "+(int)a+" "+(int)b+" at index "+i);
			}
		}
		Assert.assertTrue(Arrays.areEqual(key0, keyOut));
		
		key0 = contents0.signingPrivateKey.getBytes();
		keyOut = out.signingPrivateKey.getBytes();
		
		for(int i = 0; i<key0.length;i++){
			byte a = key0[i];
			byte b = keyOut[i];
			if(Byte.compare(a, b) != 0){
				System.err.println("different: "+(int)a+" "+(int)b+" at index "+i);
			}
		}
		Assert.assertTrue(Arrays.areEqual(key0, keyOut));
		
		key0 = contents0.agreementPrivateKey.getBytes();
		keyOut = out.agreementPrivateKey.getBytes();
		
		for(int i = 0; i<key0.length;i++){
			byte a = key0[i];
			byte b = keyOut[i];
			if(Byte.compare(a, b) != 0){
				System.err.println("different: "+(int)a+" "+(int)b+" at index "+i);
			}
		}
		Assert.assertTrue(Arrays.areEqual(key0, keyOut));
		
		
		Assert.assertNotNull(out);
	}
	
	@Test
	public void testWrapperEnc2() throws IOException {
		char [] ch0 = {'p','a','s','s'}; 
		char [] ch1 = {'p','a','s','s'}; 
		String uuidVal = "2eb1cdc9-65fe-4f3e-b029-5fd29d035ae8";
		String date = "2015-07-11T07:08:27+0000";
		EncodingHint hint = EncodingHint.Base64url;
		byte [] saltBytes = {
				's','a','l','t',
				'0','0','0','0',
				'0','0','0','0',
				'0','0','0','0',
				'0','0','0','0',
				'0','0','0','0',
				'0','0','0','0',
				'0','0','0','0',
				'0','0'};
		byte [] ivBytes = {
				'i','v','0','0',
				'0','0','0','0',
				'0','0','0','0',
				'0','0','0','0',};
		
		Password password = new NewPassword(ch0);
		SensitiveBytes salt = new SensitiveBytes(saltBytes);
		SensitiveBytes iv = new SensitiveBytes(ivBytes);
		
		PBEParams params = new PBEParams(PBEAlg.SCRYPT);
		params.setPassword(password);
		params.setSalt(salt);
		params.setIv(iv);
		params.setCpuMemoryCost_N(4);
		params.setBlockSize_r(ivBytes.length*8);
		params.setParallelization_p(32);
		params.setDesiredKeyLengthInBytes(32);
		
		KeyFormat format = new KeyFormat(hint,Mode.REQUEST_SECURE,params);
		
		C2KeyMetadata meta = new C2KeyMetadata(uuidVal, TimeUtil.getISO8601FormatDate(date), format);
		Curve25519KeyContents contents0 = new Curve25519KeyContents(
				meta,
				new PublicKey(Base64.decode(P_bad,Base64.URL_SAFE)), 
				new SigningPrivateKey(Base64.decode(s_bad,Base64.URL_SAFE)), 
				new AgreementPrivateKey(Base64.decode(k_bad,Base64.URL_SAFE))
		);
		
		JSONFormatter builder0 = new JSONFormatter("Chinese Eyes", "dave@somewhere.com");
		builder0.add(contents0);
		StringWriter writer0 = new StringWriter();
		builder0.format(writer0);
		System.err.println(writer0.toString());
		
		StringReader reader0 = new StringReader(writer0.toString());
		JSONReader jr0 = new JSONReader(reader0);
		KeyMaterials km0 = jr0.parse();
		List<CryptoKeyWrapper> wrapperList = km0.keys();
		Assert.assertTrue(wrapperList.size()==1);
		CryptoKeyWrapper keyWrapper = wrapperList.get(0);
		
		keyWrapper.unlock(new NewPassword(ch1));
		Curve25519KeyContents out = (Curve25519KeyContents) keyWrapper.getKeyContents();
		
		byte [] key0 = contents0.publicKey.getBytes();
		byte [] keyOut = out.publicKey.getBytes();
		
		for(int i = 0; i<key0.length;i++){
			byte a = key0[i];
			byte b = keyOut[i];
			if(Byte.compare(a, b) != 0){
				System.err.println("different: "+(int)a+" "+(int)b+" at index "+i);
			}
		}
		Assert.assertTrue(Arrays.areEqual(key0, keyOut));
		
		key0 = contents0.signingPrivateKey.getBytes();
		keyOut = out.signingPrivateKey.getBytes();
		
		for(int i = 0; i<key0.length;i++){
			byte a = key0[i];
			byte b = keyOut[i];
			if(Byte.compare(a, b) != 0){
				System.err.println("different: "+(int)a+" "+(int)b+" at index "+i);
			}
		}
		Assert.assertTrue(Arrays.areEqual(key0, keyOut));
		
		key0 = contents0.agreementPrivateKey.getBytes();
		keyOut = out.agreementPrivateKey.getBytes();
		
		for(int i = 0; i<key0.length;i++){
			byte a = key0[i];
			byte b = keyOut[i];
			if(Byte.compare(a, b) != 0){
				System.err.println("different: "+(int)a+" "+(int)b+" at index "+i);
			}
		}
		Assert.assertTrue(Arrays.areEqual(key0, keyOut));
		
		
		Assert.assertNotNull(out);
	}
	
	@Test
	public void testFormats() {
		C2KeyMetadata meta = C2KeyMetadata.createUnsecured();
		C2KeyMetadata metaClone = meta.clone();
		Assert.assertTrue(meta.equals(metaClone));
		
		Curve25519KeyContents contents0 = new Curve25519KeyContents(
				meta,
				new PublicKey(P), 
				new SigningPrivateKey(s), 
				new AgreementPrivateKey(k)
		);
		
		Curve25519KeyContents contents1 = new Curve25519KeyContents(
				metaClone,
				new PublicKey(P), 
				new SigningPrivateKey(s), 
				new AgreementPrivateKey(k)
		);
		
		Assert.assertTrue(contents0.equals(contents1));
		
		// prove the formatter and reader combination round trip does not modify the key integrity for an unsecured key
		Curve25519KeyContents transKey0 = key(contents0,null);
		Curve25519KeyContents transKey1 = key(contents1,null);
		Assert.assertTrue(transKey0.equals(transKey1));
		
		// prove the formatter and reader combination round trip does not modify the key integrity for a secured key
		// this is with the default alg, PBKDF2
		char [] ch0 = {'p','a','s','s'}; 
		char [] ch1 = {'p','a','s','s'}; 
		transKey0 = key(contents0.prepareSecure(PBEAlg.PBKDF2, ch0, null), new Password(ch0));
		transKey1 = key(contents0.prepareSecure(PBEAlg.PBKDF2, ch1, null), new Password(ch1));
		Assert.assertTrue(transKey0.equals(transKey1));
	}
	
	@Test
	public void testFormats1() throws IOException {
		C2KeyMetadata meta = C2KeyMetadata.createUnsecured();
		C2KeyMetadata metaClone = meta.clone();
		Assert.assertTrue(meta.equals(metaClone));
		
		Curve25519KeyContents contents0 = new Curve25519KeyContents(
				meta,
				new PublicKey(Base64.decode(P_good,Base64.URL_SAFE)), 
				new SigningPrivateKey(Base64.decode(s_good,Base64.URL_SAFE)), 
				new AgreementPrivateKey(Base64.decode(k_good,Base64.URL_SAFE))
		);
		
		Curve25519KeyContents contents1 = new Curve25519KeyContents(
				metaClone,
				new PublicKey(Base64.decode(P_good,Base64.URL_SAFE)), 
				new SigningPrivateKey(Base64.decode(s_good,Base64.URL_SAFE)), 
				new AgreementPrivateKey(Base64.decode(k_good,Base64.URL_SAFE))
		);
		
		Assert.assertTrue(contents0.equals(contents1));
		
		// prove the formatter and reader combination round trip does not modify the key integrity for an unsecured key
		Curve25519KeyContents transKey0 = key(contents0,null);
		Curve25519KeyContents transKey1 = key(contents1,null);
		Assert.assertTrue(transKey0.equals(transKey1));
		
		// prove the formatter and reader combination round trip does not modify the key integrity for a secured key
		// this is with the default alg, PBKDF2
		char [] ch0 = {'p','a','s','s'}; 
		char [] ch1 = {'p','a','s','s'}; 
		transKey0 = key(contents0.prepareSecure(PBEAlg.PBKDF2, ch0, null), new Password(ch0));
		transKey1 = key(contents0.prepareSecure(PBEAlg.PBKDF2, ch1, null), new Password(ch1));
		Assert.assertTrue(transKey0.equals(transKey1));
	}
	
	@Test
	public void testFormats2() throws IOException {
		C2KeyMetadata meta = C2KeyMetadata.createUnsecured();
		C2KeyMetadata metaClone = meta.clone();
		Assert.assertTrue(meta.equals(metaClone));
		
		Curve25519KeyContents contents0 = new Curve25519KeyContents(
				meta,
				new PublicKey(Base64.decode(P_bad,Base64.URL_SAFE)), 
				new SigningPrivateKey(Base64.decode(s_bad,Base64.URL_SAFE)), 
				new AgreementPrivateKey(Base64.decode(k_bad,Base64.URL_SAFE))
		);
		
		Curve25519KeyContents contents1 = new Curve25519KeyContents(
				metaClone,
				new PublicKey(Base64.decode(P_bad,Base64.URL_SAFE)), 
				new SigningPrivateKey(Base64.decode(s_bad,Base64.URL_SAFE)), 
				new AgreementPrivateKey(Base64.decode(k_bad,Base64.URL_SAFE))
		);
		
		Assert.assertTrue(contents0.equals(contents1));
		
		// prove the formatter and reader combination round trip does not modify the key integrity for an unsecured key
		Curve25519KeyContents transKey0 = key(contents0,null);
		Curve25519KeyContents transKey1 = key(contents1,null);
		Assert.assertTrue(transKey0.equals(transKey1));
		
		// prove the formatter and reader combination round trip does not modify the key integrity for a secured key
		// this is with the default alg, PBKDF2
		char [] ch0 = {'p','a','s','s'}; 
		char [] ch1 = {'p','a','s','s'}; 
		transKey0 = key(contents0.prepareSecure(PBEAlg.PBKDF2, ch0, null), new Password(ch0));
		transKey1 = key(contents0.prepareSecure(PBEAlg.PBKDF2, ch1, null), new Password(ch1));
		Assert.assertTrue(transKey0.equals(transKey1));
	}
	
	private Curve25519KeyContents key(Curve25519KeyContents in, Password pw){
		JSONFormatter builder0 = new JSONFormatter("Chinese Eyes");
		builder0.add(in);
		StringWriter writer0 = new StringWriter();
		builder0.format(writer0);
		System.err.println(writer0.toString());
		StringReader reader0 = new StringReader(writer0.toString());
		JSONReader jr0 = new JSONReader(reader0);
		KeyMaterials km0 = jr0.parse();
		List<CryptoKeyWrapper> wrapperList = km0.keys();
		Assert.assertTrue(wrapperList.size()==1);
		CryptoKeyWrapper keyWrapper = wrapperList.get(0);
		if(pw!=null)  keyWrapper.unlock(pw);
		return (Curve25519KeyContents) keyWrapper.getKeyContents();
	}
	
	@Test
	public void testHypothesisGoodKeys() throws IOException {
		
		CryptoContact contact = new CryptoContact("ccc1cdc9-65fe-4f3e-b029-5fd29d035ae8");
		contact.add("GivenName.0", "David");
		contact.add("GivenName.1", "Richard");
		contact.add("FamilyName.0", "Smith");
		contact.add("Address.0", "1714 Roberts Ct.");
		contact.add("City", "Madison");
		contact.add("State", "Wisconsin");
		contact.add("PostalCode", "53711");
		contact.add("CountryCode", "US");
		
		MapData ld = new MapData("aaa1cdc9-65fe-4f3e-b029-5fd29d035ae8");
		ld.put("Copyright", "\u00A9 2014, David R. Smith. All Rights Reserved");
		ld.put("License", "http://www.apache.org/licenses/LICENSE-2.0.txt");
		
		String uuidVal0 = "2eb1cdc9-65fe-4f3e-b029-5fd29d035ae8";
		String date0 = "2015-07-11T07:08:27+0000";
		EncodingHint hint = EncodingHint.Base64url;
		
		KeyFormat format0 = new KeyFormat(hint,Mode.UNSECURED,null);
		
		// load known "good" keys
		C2KeyMetadata meta = new C2KeyMetadata(uuidVal0, TimeUtil.getISO8601FormatDate(date0), format0);
		Curve25519KeyContents contents = new Curve25519KeyContents(
				meta,
				new PublicKey(Base64.decode(P_good,Base64.URL_SAFE)), 
				new SigningPrivateKey(Base64.decode(s_good,Base64.URL_SAFE)), 
				new AgreementPrivateKey(Base64.decode(k_good,Base64.URL_SAFE))
		);
		
		MapIterator iter = new C2KeyContentsIterator(contents.copyForPublication());
		MapIterator iter2 = new ContactContentsIterator(contact);
		MapIterator iter3 = new MapDataContentsIterator(ld);
	
		C2SignatureBuilder sigBuilder = new C2SignatureBuilder("SIG", TimeUtil.getISO8601FormatDate(date0), "Chinese Eyes", contents, new SHA256Digest());
		
		while(iter.hasNext()){
			String label = iter.next();
			sigBuilder.update(label, iter.get(label));
		}
		while(iter2.hasNext()){
			String label = iter2.next();
			sigBuilder.update(label, iter2.get(label));
		}
		while(iter3.hasNext()){
			String label = iter3.next();
			sigBuilder.update(label, iter3.get(label));
		}
		
		CryptoSignature sig = sigBuilder.build();
		
		JSONFormatter builder = new JSONFormatter("Chinese Eyes");
		builder.add(contact)
		.add(contents)
		.add(sig)
		.add(ld);
		//.add(rd);
		
		StringWriter writer = new StringWriter();
		builder.format(writer);
		String out = writer.toString();
		System.err.println(out);
		JSONReader reader = new JSONReader(new StringReader(out));
		KeyMaterials km = reader.parse();
		Curve25519KeyContents c = (Curve25519KeyContents ) km.keys().get(0).getKeyContents();
		SelfContainedSignatureValidator validator = new SelfContainedSignatureValidator(km,true);
		boolean ok = validator.validate();
		
		byte [] key0 = contents.publicKey.getBytes();
		byte [] keyOut = c.publicKey.getBytes();
		
		for(int i = 0; i<key0.length;i++){
			byte a = key0[i];
			byte b = keyOut[i];
			if(Byte.compare(a, b) != 0){
				System.err.println("different: "+(int)a+" "+(int)b+" at index "+i);
			}
		}
		Assert.assertTrue(Arrays.areEqual(key0, keyOut));
		
		key0 = contents.signingPrivateKey.getBytes();
		keyOut = c.signingPrivateKey.getBytes();
		
		for(int i = 0; i<key0.length;i++){
			byte a = key0[i];
			byte b = keyOut[i];
			if(Byte.compare(a, b) != 0){
				System.err.println("different: "+(int)a+" "+(int)b+" at index "+i);
			}
		}
		Assert.assertTrue(Arrays.areEqual(key0, keyOut));
		
		key0 = contents.agreementPrivateKey.getBytes();
		keyOut = c.agreementPrivateKey.getBytes();
		
		for(int i = 0; i<key0.length;i++){
			byte a = key0[i];
			byte b = keyOut[i];
			if(Byte.compare(a, b) != 0){
				System.err.println("different: "+(int)a+" "+(int)b+" at index "+i);
			}
		}
		Assert.assertTrue(Arrays.areEqual(key0, keyOut));
		
		Assert.assertTrue(ok);
	}
	
	@Test
	public void testHypothesisBadKeysMin() throws IOException{
		
		String uuidVal0 = "2eb1cdc9-65fe-4f3e-b029-5fd29d035ae8";
		String date0 = "2015-07-11T07:08:27+0000";
		EncodingHint hint = EncodingHint.Base64url;
		
		KeyFormat format0 = new KeyFormat(hint,Mode.UNSECURED,null);
		
		// load known "bad" keys
		C2KeyMetadata meta = new C2KeyMetadata(uuidVal0, TimeUtil.getISO8601FormatDate(date0), format0);
		Curve25519KeyContents contents = new Curve25519KeyContents(
				meta,
				new PublicKey(Base64.decode(P_bad,Base64.URL_SAFE)), 
				new SigningPrivateKey(Base64.decode(s_bad,Base64.URL_SAFE)), 
				new AgreementPrivateKey(Base64.decode(k_bad,Base64.URL_SAFE))
		);
		
		
		String message = "My message text...";
		byte[]msgBytes = message.getBytes(Charset.forName("UTF-8"));
		
		C2CryptoSignature sig = CryptoFactory.INSTANCE.sign("Chinese Eyes",contents, msgBytes, new SHA256Digest());
		boolean ok = CryptoFactory.INSTANCE.verify(contents, msgBytes, sig.getSignature(),new SHA256Digest());
		
		// But they work!!
		Assert.assertTrue(ok);
	}
	
	public void testKeyTransforms() {
		// as used in the code
		
	}
	
	@Test
	public void testHypothesisBadKeys() throws IOException {
		
		CryptoContact contact = new CryptoContact("ccc1cdc9-65fe-4f3e-b029-5fd29d035ae8");
		contact.add("GivenName.0", "David");
		contact.add("GivenName.1", "Richard");
		contact.add("FamilyName.0", "Smith");
		contact.add("Address.0", "1714 Roberts Ct.");
		contact.add("City", "Madison");
		contact.add("State", "Wisconsin");
		contact.add("PostalCode", "53711");
		contact.add("CountryCode", "US");
		
		MapData ld = new MapData("aaa1cdc9-65fe-4f3e-b029-5fd29d035ae8");
		ld.put("Copyright", "\u00A9 2014, David R. Smith. All Rights Reserved");
		ld.put("License", "http://www.apache.org/licenses/LICENSE-2.0.txt");
		
		String uuidVal0 = "2eb1cdc9-65fe-4f3e-b029-5fd29d035ae8";
		String date0 = "2015-07-11T07:08:27+0000";
		EncodingHint hint = EncodingHint.Base64url;
		
		KeyFormat format0 = new KeyFormat(hint,Mode.UNSECURED,null);
		
		// load known "bad" keys
		C2KeyMetadata meta = new C2KeyMetadata(uuidVal0, TimeUtil.getISO8601FormatDate(date0), format0);
		Curve25519KeyContents contents = new Curve25519KeyContents(
				meta,
				new PublicKey(Base64.decode(P_bad,Base64.URL_SAFE)), 
				new SigningPrivateKey(Base64.decode(s_bad,Base64.URL_SAFE)), 
				new AgreementPrivateKey(Base64.decode(k_bad,Base64.URL_SAFE))
		);
		
		MapIterator iter = new C2KeyContentsIterator(contents.copyForPublication());
		MapIterator iter2 = new ContactContentsIterator(contact);
		MapIterator iter3 = new MapDataContentsIterator(ld);
	
		C2SignatureCollector sigCollector = new C2SignatureCollector("SIG", TimeUtil.getISO8601FormatDate(date0), "Chinese Eyes", contents);
		
		while(iter.hasNext()){
			String label = iter.next();
			sigCollector.collect(label, iter.get(label));
		}
		while(iter2.hasNext()){
			String label = iter2.next();
			sigCollector.collect(label, iter2.get(label));
		}
		while(iter3.hasNext()){
			String label = iter3.next();
			sigCollector.collect(label, iter3.get(label));
		}
		
		CryptoSignature sig = sigCollector.build();
		
		JSONFormatter builder = new JSONFormatter("Chinese Eyes");
		builder.add(contact)
		.add(contents)
		.add(sig)
		.add(ld);
		//.add(rd);
		
		StringWriter writer = new StringWriter();
		builder.format(writer);
		String out = writer.toString();
		System.err.println(out);
		JSONReader reader = new JSONReader(new StringReader(out));
		KeyMaterials km = reader.parse();
		SelfContainedSignatureValidator validator = new SelfContainedSignatureValidator(km,true);
		boolean ok = validator.validate();
		
		byte [] sigBytes = sigCollector.getCollector().toByteArray();
		byte [] valBytes = validator.getCollector().toByteArray();
		
		for(int i = 0; i<sigBytes.length;i++){
			byte a = sigBytes[i];
			byte b = valBytes[i];
			if(Byte.compare(a, b) != 0){
				System.err.println("different: "+(int)a+" "+(int)b+" at index "+i);
			}
		}
		
		Assert.assertTrue(Arrays.areEqual(sigBytes, valBytes));
		
		Assert.assertTrue(ok);
	}
	

	@Test
	public void testGenerateKeysAndSign0() {
		
		CryptoContact contact = new CryptoContact();
		contact.add("GivenName.0", "David");
		contact.add("GivenName.1", "Richard");
		contact.add("FamilyName.0", "Smith");
		contact.add("Address.0", "1714 Roberts Ct.");
		contact.add("City", "Madison");
		contact.add("State", "Wisconsin");
		contact.add("PostalCode", "53711");
		contact.add("CountryCode", "US");
		
		MapData ld = new MapData();
		ld.put("Copyright", "\u00A9 2014, David R. Smith. All Rights Reserved");
		ld.put("License", "http://www.apache.org/licenses/LICENSE-2.0.txt");
		
		//ListData rd = new ListData();
		//rd.addURL("http://buttermilk.googlecode.com/svn/trunk/buttermilk-core/data/test0.json");
		
		Curve25519KeyContents contents = CryptoFactory.INSTANCE.generateKeys();
		MapIterator iter = new C2KeyContentsIterator(contents);
		MapIterator iter2 = new ContactContentsIterator(contact);
		MapIterator iter3 = new MapDataContentsIterator(ld);
	//	ListDataContentsIterator remoteIter = new ListDataContentsIterator(rd);
		C2SignatureBuilder sigBuilder = new C2SignatureBuilder("Chinese Eyes", contents);
		
		while(iter.hasNext()){
			String label = iter.next();
			sigBuilder.update(label, iter.get(label));
		}
		while(iter2.hasNext()){
			String label = iter2.next();
			sigBuilder.update(label, iter2.get(label));
		}
		while(iter3.hasNext()){
			String label = iter3.next();
			sigBuilder.update(label, iter3.get(label));
		}
		
		// a bit more complex - the remote iterator outputs a list resolved into LocalData
	//	while(remoteIter.hasNext()){
	//		List<MapData> list = remoteIter.nextData();
	//		for(MapData data: list){
	//			MapIterator inner = new MapDataContentsIterator(data);
	//			while(inner.hasNext()){
	//				String label = inner.next();
	//				sigBuilder.update(label, inner.get(label));
	//			}
	//		}
	//	}
		
		CryptoSignature sig = sigBuilder.build();
		
		JSONFormatter builder = new JSONFormatter("Chinese Eyes");
		builder.add(contact)
		.add(contents)
		.add(sig)
		.add(ld);
		//.add(rd);
		
		StringWriter writer = new StringWriter();
		builder.format(writer);
		String out = writer.toString();
		System.err.println(out);
		JSONReader reader = new JSONReader(new StringReader(out));
		KeyMaterials km = reader.parse();
		SelfContainedSignatureValidator validator = new SelfContainedSignatureValidator(km, true);
		boolean ok = validator.validate();
		Assert.assertTrue(ok);
	}
	
	@Test
	public void test0HypothesisGoodKeys() {
		InputStream in = this.getClass().getResourceAsStream("/believed-good-c2.json");
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
	
	@Test
	public void test0HypothesisBadKeys() {
		InputStream in = this.getClass().getResourceAsStream("/believed-bad-c2.json");
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
				Assert.assertFalse(ok);
			
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
	
	@Test
	public void test1(){
		char [] password = "password1".toCharArray();
		C2KeyMetadata meta = C2KeyMetadata.createUnsecured("TEST"); // key handle will be set to the token "TEST"
		Curve25519KeyContents keys0 = CryptoFactory.INSTANCE.generateKeys(meta);
		JSONFormatter format = new JSONFormatter("Chinese Knees");
	    format.add(keys0); // formats an unsecured key
	    format.add(keys0.prepareSecure(PBEAlg.PBKDF2, password,null)); // formats a secured clone of the key with a Base64url encoding hint, which is right for Curve25519
	    format.add(keys0.copyForPublication()); // makes a clone ready for publication
		StringWriter writer = new StringWriter();
		format.format(writer);
		String out = writer.toString();
		System.err.println(out);
		Assert.assertTrue(out.indexOf("TEST-U")>0);
		Assert.assertTrue(out.indexOf("TEST-S")>0);
		Assert.assertTrue(out.indexOf("TEST-P")>0);
		//System.err.println(out);
	}
	
	

}
