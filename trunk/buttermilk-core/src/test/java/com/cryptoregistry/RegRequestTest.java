package com.cryptoregistry;

import java.io.StringReader;
import java.io.StringWriter;
import java.util.ArrayList;
import java.util.List;

import junit.framework.Assert;

import org.junit.Test;

import com.cryptoregistry.c2.key.Curve25519KeyContents;
import com.cryptoregistry.c2.key.Curve25519KeyForPublication;
import com.cryptoregistry.ec.CurveFactory;
import com.cryptoregistry.ec.ECKeyContents;
import com.cryptoregistry.ec.ECKeyForPublication;
import com.cryptoregistry.formats.JSONFormatter;
import com.cryptoregistry.formats.JSONReader;
import com.cryptoregistry.rsa.RSAKeyContents;
import com.cryptoregistry.rsa.RSAKeyForPublication;
import com.cryptoregistry.rsa.RSAKeyMetadata;
import com.cryptoregistry.signature.C2CryptoSignature;
import com.cryptoregistry.signature.ECDSACryptoSignature;
import com.cryptoregistry.signature.RSACryptoSignature;
import com.cryptoregistry.signature.builder.C2KeyContentsIterator;
import com.cryptoregistry.signature.builder.C2SignatureBuilder;
import com.cryptoregistry.signature.builder.ContactContentsIterator;
import com.cryptoregistry.signature.builder.ECDSASignatureBuilder;
import com.cryptoregistry.signature.builder.ECKeyContentsIterator;
import com.cryptoregistry.signature.builder.MapDataContentsIterator;
import com.cryptoregistry.signature.builder.RSAKeyContentsIterator;
import com.cryptoregistry.signature.builder.RSASignatureBuilder;
import com.cryptoregistry.signature.validator.SelfContainedSignatureValidator;
import com.cryptoregistry.util.MapIterator;

public class RegRequestTest {
	
	@Test
	public void test0() {
		this.createSignatures();
	}
	
	
	/**
	 * Build a list of a variety of keys 
	 * 
	 * @param alg
	 * @return
	 */
	private List<CryptoKey> buildKeys(KeyGenerationAlgorithm keyAlg){
		List<CryptoKey> list = new ArrayList<CryptoKey>();
		switch(keyAlg){
			case Curve25519: {
				list.add(com.cryptoregistry.c2.CryptoFactory.INSTANCE.generateKeys());
				break;
			}
			case EC: {
				for(CurveFactory.CurveName c: CurveFactory.CurveName.values()){
					list.add(com.cryptoregistry.ec.CryptoFactory.INSTANCE.generateKeys(c.name()));
				}
				break;
			}
			case RSA: {
				int [] strengths = new int[3];
				strengths[0]=1024;
				strengths[1]=2048;
				strengths[2]=4096;
				
				for(com.cryptoregistry.rsa.CryptoFactory.PUBLIC_EXPONENTS px: com.cryptoregistry.rsa.CryptoFactory.PUBLIC_EXPONENTS.values()){
				 for(int strength:strengths){
					list.add(com.cryptoregistry.rsa.CryptoFactory.INSTANCE.generateKeys(
						RSAKeyMetadata.createDefault(), 
						px, 
						strength, 
						80));
				 }
				}
				break;
			}
			default:{}
		}
		
		return list;
	}

	
	private void createSignatures() {
		
		MapData affirmations = new MapData();
		affirmations.put("Copyright", "© 2015 DAVE SMITH, All Rights Reserved");
		affirmations.put("TermsOfServiceAgreement", "I agree to the terms of service.");
		affirmations.put("InfoAffirmation", "I agree this information is correct and complete");
		
		String _regHandle = "The Dirty Monkey";
		String privateEmail = "dave@cryptoregistry.com";
		
		CryptoContact c0 = new CryptoContact();
		c0.add("Address.0", "Unit 1");
		c0.add("Address.1", "1714 Roberts Ct.");
		c0.add("City", "Somewhereville");
		c0.add("StateOrProvince", "NSW");
		c0.add("Country", "AU");
		c0.add("PostalCode", "2251");
		
		CryptoContact c1 = new CryptoContact();
		c1.add("Address.0", "Unit 2");
		c1.add("Address.1", "");
		c1.add("City", "Different");
		c1.add("StateOrProvince", "NSW");
		c1.add("Country", "AU");
		c1.add("PostalCode", "2251");
		
		
		List<CryptoContact> contacts = new ArrayList<CryptoContact>();
		contacts.add(c0);
		contacts.add(c1);
		
		int count = 0;
			
		//	List<CryptoKey> secureKeys = buildKeys(keyAlg);
			List<CryptoKey> secureKeys = new ArrayList<CryptoKey>();
			secureKeys.add(com.cryptoregistry.c2.CryptoFactory.INSTANCE.generateKeys());
		//	secureKeys.add(com.cryptoregistry.ec.CryptoFactory.INSTANCE.generateKeys("P-256"));
		//	secureKeys.add(com.cryptoregistry.rsa.CryptoFactory.INSTANCE.generateKeys());
			for(int i = 0;i<10;i++){
			   for(CryptoKey confidentialKey: secureKeys){
				   
				 String regHandle = _regHandle;
		
				JSONFormatter requestFormatter = new JSONFormatter(regHandle,privateEmail);
				CryptoKey pubKey = confidentialKey.keyForPublication();
				
				MapIterator iter = null;
				
				switch(confidentialKey.getMetadata().getKeyAlgorithm()){
		
					case Curve25519: {
						Curve25519KeyForPublication pub = (Curve25519KeyForPublication) pubKey;
						C2SignatureBuilder sigBuilder = new C2SignatureBuilder(regHandle, (Curve25519KeyContents) confidentialKey);
						iter = new C2KeyContentsIterator(pub);
						// key contents
						while(iter.hasNext()){
							String label = iter.next();
							sigBuilder.update(label, iter.get(label));
						}
						requestFormatter.add(confidentialKey);
						
						// contacts
						/*
						for(CryptoContact contact: contacts){
							iter = new ContactContentsIterator(contact);
							while(iter.hasNext()){
								String label = iter.next();
								sigBuilder.update(label, iter.get(label));
							}
							requestFormatter.add(contact);
						}
						
						// affirmations - MapData
						iter = new MapDataContentsIterator(affirmations);
						while(iter.hasNext()){
							String label = iter.next();
							sigBuilder.update(label, iter.get(label));
						}
						requestFormatter.add(affirmations);
						*/
						
						C2CryptoSignature sig = sigBuilder.build();
						requestFormatter.add(sig);
						
						break;
					}
					case EC: {
						ECKeyForPublication pub = (ECKeyForPublication) pubKey;
						ECDSASignatureBuilder sigBuilder = new ECDSASignatureBuilder(regHandle, (ECKeyContents) confidentialKey);
						iter = new ECKeyContentsIterator(pub);
						// key contents
						while(iter.hasNext()){
							String label = iter.next();
							sigBuilder.update(label, iter.get(label));
						}
						requestFormatter.add(pub);
						
						// contacts
						for(CryptoContact contact: contacts){
							iter = new ContactContentsIterator(contact);
							while(iter.hasNext()){
								String label = iter.next();
								sigBuilder.update(label, iter.get(label));
							}
							requestFormatter.add(contact);
						}
						// affirmations - MapData
						iter = new MapDataContentsIterator(affirmations);
						while(iter.hasNext()){
							String label = iter.next();
							sigBuilder.update(label, iter.get(label));
						}
						requestFormatter.add(affirmations);
						
						ECDSACryptoSignature sig = sigBuilder.build();
						requestFormatter.add(sig);
					
						break;
					}
					case RSA: {
						RSAKeyForPublication pub = (RSAKeyForPublication) pubKey;
						RSASignatureBuilder sigBuilder = new RSASignatureBuilder(regHandle, (RSAKeyContents) confidentialKey);
						iter = new RSAKeyContentsIterator(pub);
						// key contents
						while(iter.hasNext()){
							String label = iter.next();
							String value = iter.get(label);
							sigBuilder.update(label, value);
						}
						requestFormatter.add(pub);
						
						// contacts
						for(CryptoContact contact: contacts){
							iter = new ContactContentsIterator(contact);
							while(iter.hasNext()){
								String label = iter.next();
								sigBuilder.update(label, iter.get(label));
							}
							requestFormatter.add(contact);
						}
					
						// affirmations - MapData
						iter = new MapDataContentsIterator(affirmations);
						while(iter.hasNext()){
							String label = iter.next();
							sigBuilder.update(label, iter.get(label));
						}
						requestFormatter.add(affirmations);
						
						RSACryptoSignature sig = sigBuilder.build();
						requestFormatter.add(sig);
						break;
					}
					
					default: { 
						// nothing
					}
				}// end of switch
				
				
					StringWriter writer = new StringWriter();
					requestFormatter.format(writer);
					String output = writer.toString();
					//	System.err.println(output);
				 
					JSONReader js = new JSONReader(new StringReader(output));
					KeyMaterials km = js.parse();
					SelfContainedSignatureValidator validator = new SelfContainedSignatureValidator(km);
					boolean ok = validator.validate();
					System.err.println(confidentialKey.getMetadata().getHandle()+" "+confidentialKey.getMetadata().getKeyAlgorithm().toString()+" "+ok);
					Assert.assertTrue(ok);
			   }
			}
	}//end of method
	
	
	

}
