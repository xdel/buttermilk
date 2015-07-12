package com.cryptoregistry.formats;

import org.junit.Assert;
import org.junit.Test;

import com.cryptoregistry.CryptoKey;
import com.cryptoregistry.c2.CryptoFactory;
import com.cryptoregistry.c2.key.Curve25519KeyContents;
import com.cryptoregistry.passwords.Password;
import com.cryptoregistry.pbe.ArmoredPBEResult;
import com.cryptoregistry.pbe.PBEParamsFactory;

public class KeyEncryptorTest {

	@Test
	public void test(){
		char [] ch0 = {'p','a','s','s',};
		Curve25519KeyContents c2Keys = CryptoFactory.INSTANCE.generateKeys();
		KeyEncryptor enc = new KeyEncryptor(new KeyHolder(c2Keys));
		ArmoredPBEResult result = enc.wrap(PBEParamsFactory.INSTANCE.createPBKDF2Params(ch0));
		KeyDecryptor dec = new KeyDecryptor(result,new Password(ch0));
		CryptoKey key = dec.unwrap();
		Assert.assertTrue(key instanceof Curve25519KeyContents);
	}

}
