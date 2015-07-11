package com.cryptoregistry.formats;

import java.io.StringReader;
import java.io.StringWriter;
import java.util.List;

import org.junit.Assert;
import org.junit.Test;

import com.cryptoregistry.CryptoContact;
import com.cryptoregistry.CryptoKeyWrapper;
import com.cryptoregistry.KeyMaterials;
import com.cryptoregistry.MapData;
import com.cryptoregistry.ListData;
import com.cryptoregistry.c2.CryptoFactory;
import com.cryptoregistry.c2.key.AgreementPrivateKey;
import com.cryptoregistry.c2.key.C2KeyMetadata;
import com.cryptoregistry.c2.key.Curve25519KeyContents;
import com.cryptoregistry.c2.key.PublicKey;
import com.cryptoregistry.c2.key.SigningPrivateKey;
import com.cryptoregistry.passwords.NewPassword;
import com.cryptoregistry.passwords.Password;
import com.cryptoregistry.passwords.SensitiveBytes;
import com.cryptoregistry.pbe.PBE;
import com.cryptoregistry.pbe.PBEAlg;
import com.cryptoregistry.pbe.PBEParams;
import com.cryptoregistry.pbe.PBEParamsFactory;
import com.cryptoregistry.signature.CryptoSignature;
import com.cryptoregistry.signature.builder.C2KeyContentsIterator;
import com.cryptoregistry.signature.builder.C2SignatureBuilder;
import com.cryptoregistry.signature.builder.ContactContentsIterator;
import com.cryptoregistry.signature.builder.MapDataContentsIterator;
import com.cryptoregistry.signature.builder.ListDataContentsIterator;
import com.cryptoregistry.util.MapIterator;
import com.cryptoregistry.util.TimeUtil;


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
	
	@Test
	public void testWrapperEnc() {
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
		
		KeyFormat format = new KeyFormat(hint,params);
		
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
		transKey0 = key(contents0.clone(new KeyFormat(ch0)), new Password(ch0));
		transKey1 = key(contents0.clone(new KeyFormat(ch1)), new Password(ch1));
		Assert.assertTrue(transKey0.equals(transKey1));
		
		// prove cloning for secure mode makes correct clones for scrypt
		byte [] iv0 = {'0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0'};
		byte [] iv1 = {'0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0'};
		char[] p0= {'p','a','s','s','w','o','r','d'};
		char[] p1= {'p','a','s','s','w','o','r','d'};
		Password pass0 = new NewPassword(p0);
		Password pass1 = new NewPassword(p1);
		byte [] salt0 = {
				's','a','l','t',
				'0','0','0','0',
				'0','0','0','0',
				'0','0','0','0',
				'0','0','0','0',
				'0','0','0','0',
				'0','0','0','0',
				'0','0','0','0',
				'0','0'};
		byte [] salt1 = {
				's','a','l','t',
				'0','0','0','0',
				'0','0','0','0',
				'0','0','0','0',
				'0','0','0','0',
				'0','0','0','0',
				'0','0','0','0',
				'0','0','0','0',
				'0','0'};
		SensitiveBytes sb0 = new SensitiveBytes(salt0);
		SensitiveBytes sb1 = new SensitiveBytes(salt1);
		
		PBEParams params0 = new PBEParams(PBEAlg.SCRYPT);
		params0.setPassword(pass0);
		params0.setSalt(sb0);
		params0.setIv(new SensitiveBytes(iv0));
		params0.setBlockSize_r(128);
		params0.setCpuMemoryCost_N(4);
		params0.setParallelization_p(32);
		
		PBEParams params1 = new PBEParams(PBEAlg.SCRYPT);
		params1.setPassword(pass1);
		params1.setSalt(sb1);
		params1.setIv(new SensitiveBytes(iv1));
		params1.setBlockSize_r(128);
		params1.setCpuMemoryCost_N(4);
		params1.setParallelization_p(32);
		
		// clone with scrypt settings for the secured formatting, validate they are equal
		transKey0 =contents0.clone(
				new KeyFormat(
					EncodingHint.Base64url,
					params0
				)
		); 
		
		transKey1 =contents1.clone(
				new KeyFormat(
					EncodingHint.Base64url,
					params0
				)
		); 			
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
	public void test0() {
		
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
		
		ListData rd = new ListData();
		rd.addURL("http://buttermilk.googlecode.com/svn/trunk/buttermilk-core/data/test0.json");
		
		Curve25519KeyContents contents = CryptoFactory.INSTANCE.generateKeys();
		MapIterator iter = new C2KeyContentsIterator(contents);
		MapIterator iter2 = new ContactContentsIterator(contact);
		MapIterator iter3 = new MapDataContentsIterator(ld);
		ListDataContentsIterator remoteIter = new ListDataContentsIterator(rd);
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
		while(remoteIter.hasNext()){
			List<MapData> list = remoteIter.nextData();
			for(MapData data: list){
				MapIterator inner = new MapDataContentsIterator(data);
				while(inner.hasNext()){
					String label = inner.next();
					sigBuilder.update(label, inner.get(label));
				}
			}
		}
		
		CryptoSignature sig = sigBuilder.build();
		
		JSONFormatter builder = new JSONFormatter("Chinese Eyes");
		builder.add(contact)
		.add(contents)
		.add(sig)
		.add(ld)
		.add(rd);
		
		StringWriter writer = new StringWriter();
		builder.format(writer);
		String output = writer.toString();
		
		Assert.assertTrue(output != null);
		
		System.err.println(output);
		
	}
	
	@Test
	public void test1(){
		char [] password = "password1".toCharArray();
		C2KeyMetadata meta = C2KeyMetadata.createUnsecured("TEST"); // key handle will be set to the token "TEST"
		Curve25519KeyContents keys0 = CryptoFactory.INSTANCE.generateKeys(meta);
		JSONFormatter format = new JSONFormatter("Chinese Knees");
	    format.add(keys0); // formats an unsecured key
	    format.add(keys0.clone(new KeyFormat(password))); // formats a secured clone of the key with a Base64url encoding hint, which is right for Curve25519
	    format.add(keys0.cloneForPublication()); // makes a clone ready for publication
		StringWriter writer = new StringWriter();
		format.format(writer);
		String out = writer.toString();
		Assert.assertTrue(out.indexOf("TEST-U")>0);
		Assert.assertTrue(out.indexOf("TEST-S")>0);
		Assert.assertTrue(out.indexOf("TEST-P")>0);
		//System.err.println(out);
	}
	
	

}
