package com.cryptoregistry.signature.validator;

import java.io.ByteArrayOutputStream;
import java.util.List;

import x.org.bouncycastle.crypto.digests.SHA256Digest;

import com.cryptoregistry.CryptoKey;
import com.cryptoregistry.CryptoKeyWrapper;
import com.cryptoregistry.KeyMaterials;
import com.cryptoregistry.SignatureAlgorithm;
import com.cryptoregistry.c2.key.Curve25519KeyForPublication;
import com.cryptoregistry.ec.ECKeyForPublication;
import com.cryptoregistry.rsa.RSAKeyForPublication;
import com.cryptoregistry.signature.C2CryptoSignature;
import com.cryptoregistry.signature.CryptoSignature;
import com.cryptoregistry.signature.RefNotFoundException;
import com.cryptoregistry.signature.SelfContainedJSONResolver;

/**
 * Fail if) 
 * 	1) no signatures found
 * 	2) Key used for signing is not found, or not public 
 * 
 * @author Dave
 *
 */
public class SelfContainedSignatureValidator {

	private KeyMaterials km;
	
	private SelfContainedSignatureValidator(){}

	public SelfContainedSignatureValidator(KeyMaterials km) {
		this();
		this.km = km;
	}
	
	/**
	 * Validate all signatures found in this KeyMaterials Object. All required tokens are expected to be present
	 * 
	 * @return
	 */
	public boolean validate() {
		
		// step 1.0: validate there is at least one signature to test
		List<CryptoSignature> sigs = km.signatures();
		if(sigs == null || sigs.size() ==0) {
			throw new RuntimeException("No signatures to validate");
		}
		
		// step 1.1: Prepare and load the resolver internal cache
		SelfContainedJSONResolver resolver = new SelfContainedJSONResolver(km.baseMap());
		resolver.walk();
		
		// step 1.2: for each signature, validate
		for(CryptoSignature sig: sigs){
			
			// step 1.2.0: collect the data the signature was made against.
			// Fail if a token is not found or some other error occurs
			ByteArrayOutputStream collector = new ByteArrayOutputStream();
			try {
				resolver.resolve(sig.getDataRefs(), collector);
			} catch (RefNotFoundException e) {
				throw new RuntimeException(e);
			}
			byte [] bytes = collector.toByteArray();
			
			//step 1.2.1: get the key used for this signature
			String keyUUID = sig.getSignedWith();
			List<CryptoKeyWrapper> keys = km.keys();
			CryptoKey key = null;
			for(CryptoKeyWrapper wrapper: keys){
				if(wrapper.getMetadata().getHandle().equals(keyUUID) && wrapper.isForPublication()){
					key = wrapper.getKeyContents();
				}
			}
			
			// step 1.2.2: see if key was found, if not, then fail
			if(key == null) throw new RuntimeException("Could not find required key: "+key);
			
			// step 1.2.3: do validation based on signature algorithm type, bail if not valid
			boolean valid = false;
			SignatureAlgorithm sigAlg = SignatureAlgorithm.valueOf(sig.getSigAlg());
			switch(sigAlg){
				case RSA: {
					valid = validateRSA(sig, (RSAKeyForPublication)key, bytes);
					if(!valid) return false;
					break;
				}
				case ECDSA: {
					valid = validateEC(sig, (ECKeyForPublication)key, bytes);
					if(!valid) return false;
					break;
				}
				case ECKCDSA: {
					valid = validateC2((C2CryptoSignature)sig, (Curve25519KeyForPublication)key, bytes);
					if(!valid) return false;
					break;
				}
				default: throw new RuntimeException("Unimplemented signature algorithm: "+sigAlg);
			}
		}
		
		return true;
	}
	
	private boolean validateRSA(CryptoSignature sig, RSAKeyForPublication key, byte [] sourceBytes){
		
		return false;
	}
	
	private boolean validateEC(CryptoSignature sig, ECKeyForPublication key, byte [] sourceBytes){
		
		return false;
	}
	
	private boolean validateC2(C2CryptoSignature sig, Curve25519KeyForPublication key, byte [] sourceBytes){
		SHA256Digest digest = new SHA256Digest();
		digest.update(sourceBytes, 0, sourceBytes.length);
		byte [] m = new byte[digest.getDigestSize()];
		digest.doFinal(m, 0);
		return  com.cryptoregistry.c2.CryptoFactory.INSTANCE.verify(key, m, sig.getSignature());
		
	}

}
