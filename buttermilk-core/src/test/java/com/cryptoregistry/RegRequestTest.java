package com.cryptoregistry;

import java.io.StringReader;
import java.io.StringWriter;

import junit.framework.Assert;

import org.junit.Test;

import com.cryptoregistry.c2.key.C2KeyMetadata;
import com.cryptoregistry.c2.key.Curve25519KeyContents;
import com.cryptoregistry.c2.key.Curve25519KeyForPublication;
import com.cryptoregistry.formats.JSONFormatter;
import com.cryptoregistry.formats.JSONReader;
import com.cryptoregistry.passwords.Password;
import com.cryptoregistry.signature.C2CryptoSignature;
import com.cryptoregistry.signature.builder.C2KeyContentsIterator;
import com.cryptoregistry.signature.builder.C2SignatureCollector;
import com.cryptoregistry.signature.builder.ContactContentsIterator;
import com.cryptoregistry.signature.builder.MapDataContentsIterator;
import com.cryptoregistry.signature.validator.SelfContainedSignatureValidator;
import com.cryptoregistry.util.MapIterator;

public class RegRequestTest {

	@Test
	public void test0() {
		this.createSignatures();
	}

	private void createSignatures() {

		String regHandle = "The IT Girl";
		String privateEmail = "dave@cryptoregistry.com";

		MapData affirmations = new MapData();
		affirmations.put("Copyright", "© 2015 DAVE SMITH, All Rights Reserved");
		affirmations.put("TermsOfServiceAgreement",
				"I agree to the terms of service.");
		affirmations.put("InfoAffirmation",
				"I agree this information is correct and complete");

		CryptoContact c0 = new CryptoContact();
		c0.add("Address.0", "Unit 1");
		c0.add("Address.1", "1714 Roberts Ct.");
		c0.add("City", "Somewhereville");
		c0.add("StateOrProvince", "NSW");
		c0.add("Country", "AU");
		c0.add("PostalCode", "2251");

		char[] pass = { 'p', 'a', 's', 's' };
		C2KeyMetadata meta = C2KeyMetadata.createSecurePBKDF2(pass);
		CryptoKey confidentialKey = com.cryptoregistry.c2.CryptoFactory.INSTANCE.generateKeys(meta);

		JSONFormatter requestFormatter = new JSONFormatter(regHandle,privateEmail);
		CryptoKey pubKey = confidentialKey.keyForPublication();

		MapIterator iter = null;

		Curve25519KeyForPublication pub = (Curve25519KeyForPublication) pubKey;
		C2SignatureCollector sigBuilder = new C2SignatureCollector(regHandle,
				(Curve25519KeyContents) confidentialKey);
		sigBuilder.setDebugMode(true);
		iter = new C2KeyContentsIterator(pub);
		// key contents
		while (iter.hasNext()) {
			String label = iter.next();
			sigBuilder.collect(label, iter.get(label));
		}
		requestFormatter.add(pub);

		// contacts

			iter = new ContactContentsIterator(c0);
			while (iter.hasNext()) {
				String label = iter.next();
				sigBuilder.collect(label, iter.get(label));
			}
			requestFormatter.add(c0);

		// affirmations - MapData
		iter = new MapDataContentsIterator(affirmations);
		while (iter.hasNext()) {
			String label = iter.next();
			sigBuilder.collect(label, iter.get(label));
		}
		requestFormatter.add(affirmations);

		C2CryptoSignature sig = sigBuilder.build();
		requestFormatter.add(sig);

		StringWriter writer = new StringWriter();
		requestFormatter.format(writer);
		String output = writer.toString();
		System.err.println(output);

		JSONReader js = new JSONReader(new StringReader(output));
		KeyMaterials km = js.parse();
		char[] pass1 = { 'p', 'a', 's', 's' };
		km.keys().get(0).unlock(new Password(pass1));
		SelfContainedSignatureValidator validator = new SelfContainedSignatureValidator(km);
		boolean ok = validator.validate();
		Assert.assertTrue(ok);

	}

}
