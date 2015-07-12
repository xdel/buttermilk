package com.cryptoregistry.signature.builder;

import junit.framework.Assert;

import org.junit.Test;

import com.cryptoregistry.c2.key.AgreementPrivateKey;
import com.cryptoregistry.c2.key.C2KeyMetadata;
import com.cryptoregistry.c2.key.Curve25519KeyContents;
import com.cryptoregistry.c2.key.PublicKey;
import com.cryptoregistry.c2.key.SigningPrivateKey;
import com.cryptoregistry.formats.EncodingHint;
import com.cryptoregistry.formats.KeyFormat;
import com.cryptoregistry.util.TimeUtil;

public class C2KeyContentsIteratorTest {

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
	public void test0() {
		
		KeyFormat format = KeyFormat.securedPBKDF2(passwordChars);
		
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
	//	Curve25519KeyForPublication pub = contents0.prepareForPublication();
		C2KeyContentsIterator iter = new C2KeyContentsIterator(contentsClone);
		while(iter.hasNext()){
			String key = iter.next();
			System.err.printf("%s = %s\n", key, iter.get(key));
		}
		
		// prove only public parts are capable of being listed
		Assert.assertTrue(iter.map.size()==4);
		
	}

}
