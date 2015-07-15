package com.cryptoregistry.signature.validator;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

import net.iharder.Base64;
import x.org.bouncycastle.crypto.Digest;
import x.org.bouncycastle.crypto.digests.SHA1Digest;

import com.cryptoregistry.CryptoKey;
import com.cryptoregistry.CryptoKeyWrapper;
import com.cryptoregistry.KeyMaterials;
import com.cryptoregistry.SignatureAlgorithm;
import com.cryptoregistry.c2.key.Curve25519KeyForPublication;
import com.cryptoregistry.ec.ECKeyForPublication;
import com.cryptoregistry.rsa.RSAKeyForPublication;
import com.cryptoregistry.signature.C2CryptoSignature;
import com.cryptoregistry.signature.ECDSACryptoSignature;
import com.cryptoregistry.signature.RSACryptoSignature;
import com.cryptoregistry.signature.CryptoSignature;
import com.cryptoregistry.signature.RefNotFoundException;
import com.cryptoregistry.signature.SelfContainedJSONResolver;


/**
 * <p>Validate a Buttermilk 1.0 formatted json file, typically a registration file. All references are expected to be
 * present in the file, although we have limited support for HTTP and FILE urls (as "remote" references.)<p>
 * 
 * <p>Fail if)</p>
 * <ol><li>
 * 	no signatures found
 * </li>
 * <li>
 * 	 Key used for signing is not found, or not public (e.g., in armored format)
 * </li>
 * </ol>
 * 
 * <p>Example</p>
 * <pre>
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
			SHA256Digest digest = new SHA256Digest();
			digest.update(msgBytes, 0, msgBytes.length);
			byte [] m = new byte[digest.getDigestSize()];
			digest.doFinal(m, 0);
			
			boolean ok = CryptoFactory.INSTANCE.verify(sig, rKeys, m);
			Assert.assertTrue(ok);
		} catch (RefNotFoundException e) {
			e.printStackTrace();
		}
		
This code above generates and validates the following data structure when formatted:

{
  "Version" : "Buttermilk Key Materials 1.0",
  "RegHandle" : "Chinese Eyes",
  "Email" : "",
  "Data" : {
    "Local" : {
      "46b3b5d8-3487-4b9d-a01f-2a03aa8e0d98" : {
        "Msg" : "My message text..."
      }
    }
  },
  "Keys" : {
    "f250a75d-a990-4d0d-8afb-0b7a0190554c-U" : {
      "KeyAlgorithm" : "EC",
      "CreatedOn" : "2015-06-21T00:08:19+0000",
      "Encoding" : "Base64url",
      "Q" : "GhVXqkLqfzq0sCeqAFZPR-zOsGyMtiVZrXvtnEI-dlI=,ALhWjPeRpek5RP6qwjsXQ6R3UtVPpqwpBxpRXr_1DyJ6",
      "D" : "AIda_dEida3bPNq6yS12XuJZZQK3MBGRMc1iNJ0kvPrx",
      "CurveName" : "P-256"
    }
  },
  "Signatures" : {
    "67f017e3-38b2-4d1a-854d-c9a0f164e6d3" : {
      "CreatedOn" : "2015-06-21T00:08:19+0000",
      "SignedWith" : "f250a75d-a990-4d0d-8afb-0b7a0190554c",
      "SignedBy" : "Chinese Eyes",
      "SignatureAlgorithm" : "ECDSA",
      "DigestAlgorithm" : "SHA-1",
      "r" : "c23250e64706bce3d7640f28243b83ae9973b3ce0da289c0928e45a3f3d6c785",
      "s" : "4f78247ef6848e58a730d82b2260636b81f5e3eeac3bc7154d3367b02e340d1e",
      "DataRefs" : "67f017e3-38b2-4d1a-854d-c9a0f164e6d3:SignedBy, .SignedWith, 46b3b5d8-3487-4b9d-a01f-2a03aa8e0d98:Msg"
    }
  }
}

 
  </pre>
 * 
 * @author Dave
 *
 */
public class SelfContainedSignatureValidator {

	private final KeyMaterials km;
	private SelfContainedJSONResolver resolver;
	private boolean debugMode;
	ByteArrayOutputStream collector;
	
	public SelfContainedSignatureValidator(KeyMaterials km) {
		this.km = km;
		this.debugMode = false;
	}
	
	/**
	 * Turn on debug mode
	 * 
	 * @param km
	 * @param debug
	 */
	public SelfContainedSignatureValidator(KeyMaterials km, boolean debug) {
		this.km = km;
		this.debugMode = debug;
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
		resolver = new SelfContainedJSONResolver(km.baseMap());
		resolver.setDebugMode(debugMode);
		resolver.walk();
		if(debugMode) {
			Map<String,String> map = resolver.getCache();
			TreeMap<String,String> tree = new TreeMap<String,String>(map);
			Iterator<String> iter = tree.keySet().iterator();
			System.err.println("Resolver pool has "+tree.size()+ " members");
			System.err.println("****************Resolver cache **************");
			while(iter.hasNext()){
				String key = iter.next();
				Object obj = tree.get(key);
				System.err.format("%s = %s\n", key, obj);
			}
			System.err.println("*************End Resolver cache **************");
		}
		
		// step 1.2: for each signature, validate
		for(CryptoSignature sig: sigs){
			
			// step 1.2.0: collect the data the signature was made against.
			// Fail if a token is not found or some other error occurs
			collector = new ByteArrayOutputStream();
			try {
				resolver.resolve(sig.getDataRefs(), collector);
			} catch (RefNotFoundException e) {
				throw new RuntimeException(e);
			}
			byte [] bytes = collector.toByteArray();
			
			//step 1.2.1: get the for-publication key used for this signature - assumption is that it is present; if not, fail
			String keyUUID = sig.getSignedWith();
			List<CryptoKeyWrapper> keys = km.keys();
			CryptoKey key = null;
			for(CryptoKeyWrapper wrapper: keys){
				if(keyUUID.equals(wrapper.getMetadata().getHandle())){
					key = wrapper.getKeyContents();
				}
			}
			
			// step 1.2.2: see if key was found, if not, then fail
			if(key == null) throw new RuntimeException("Could not find required 'SignedWith' key, it is assumed to be present for this to work: "+keyUUID);
			
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
		Digest digest = sig.getDigestInstance();
		digest.update(sourceBytes, 0, sourceBytes.length);
		byte [] m = new byte[digest.getDigestSize()];
		digest.doFinal(m, 0);
		return com.cryptoregistry.rsa.CryptoFactory.INSTANCE.verify((RSACryptoSignature)sig, key, m);
	}
	
	private boolean validateEC(CryptoSignature sig, ECKeyForPublication key, byte [] sourceBytes){
		Digest digest = sig.getDigestInstance();
		digest.update(sourceBytes, 0, sourceBytes.length);
		byte [] m = new byte[digest.getDigestSize()];
		digest.doFinal(m, 0);
		return com.cryptoregistry.ec.CryptoFactory.INSTANCE.verify((ECDSACryptoSignature)sig, key, m);
	}
	
	/**
	 * For C2 we do not digest first, we pass in the whole sourceBytes. Use C2SignatureCollector with this 
	 * one (not C2SignatureBuilder).
	 * @param sig
	 * @param key
	 * @param sourceBytes
	 * @return
	 */
	private boolean validateC2(C2CryptoSignature sig, Curve25519KeyForPublication key, byte [] sourceBytes){
		Digest digest = sig.getDigestInstance();
	//	digest.update(sourceBytes, 0, sourceBytes.length);
	//	byte [] m = new byte[digest.getDigestSize()];
	//	digest.doFinal(m, 0);
	//	digest.reset();
		
		if(debugMode){
			SHA1Digest td = new SHA1Digest();
			td.update(sourceBytes, 0, sourceBytes.length);
			byte [] result = new byte[td.getDigestSize()];
			td.doFinal(result, 0);
			try {
				System.err.println("Bytes: "+Base64.encodeBytes(sourceBytes, Base64.URL_SAFE));
				System.err.println("Check: "+Base64.encodeBytes(result, Base64.URL_SAFE));
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
		
		return  com.cryptoregistry.c2.CryptoFactory.INSTANCE.verify(key, sourceBytes, sig.getSignature(), digest);
	}

	public boolean isDebugMode() {
		return debugMode;
	}

	public void setDebugMode(boolean debugMode) {
		this.debugMode = debugMode;
		if(resolver != null) resolver.setDebugMode(debugMode);
	}

	public SelfContainedJSONResolver getResolver() {
		return resolver;
	}

	public void setResolver(SelfContainedJSONResolver resolver) {
		this.resolver = resolver;
	}

	public ByteArrayOutputStream getCollector() {
		return collector;
	}

}
