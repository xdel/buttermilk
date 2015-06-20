package com.cryptoregistry.formats.simplereader;

import java.io.IOException;
import java.io.Reader;
import java.math.BigInteger;
import java.util.Date;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import com.cryptoregistry.SignatureAlgorithm;
import com.cryptoregistry.signature.C2CryptoSignature;
import com.cryptoregistry.signature.C2Signature;
import com.cryptoregistry.signature.CryptoSignature;
import com.cryptoregistry.signature.ECDSACryptoSignature;
import com.cryptoregistry.signature.ECDSASignature;
import com.cryptoregistry.signature.RSACryptoSignature;
import com.cryptoregistry.signature.RSASignature;
import com.cryptoregistry.signature.SignatureMetadata;
import com.cryptoregistry.util.ArmoredString;
import com.cryptoregistry.util.TimeUtil;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * Read an individual signature block, such as
 * 
 * {
    "52701823-dcae-440e-a881-8311cf7e5f03" : {
      "CreatedOn" : "2015-04-04T04:43:14+0000",
      "SignedWith" : "4073611e-0c56-4f33-99ba-66faa6fc53ab",
      "SignedBy" : "The IT Girl",
      "SignatureAlgorithm" : "ECKCDSA",
      "DigestAlgorithm" : "SHA-256",
      "v" : "J60Qj4GeRndjwZHjcW3FrjxNZRdHKLjYkSrzIpp_JgA=",
      "r" : "ymwgBZJYE8cBNJZvH4BLFOtqGLlm4CzKK6l5YzPcn2Q=",
      "DataRefs" : "6e578818-9108-401d-835e-d399c72d0427:SignedBy, .SignedWith, 4073611e-0c56-4f33-99ba-66faa6fc53ab:Handle, .CreatedOn, .Algorithm, .P, 9b570d10-fdc2-4ef3-9d52-6a3bcba15c55:contactType, .GivenName.0, .FamilyName.0, .Email.0, .MobilePhone.0, .Country, 07e4f62a-88d8-478d-8cf6-cf7e535a53b5:Copyright, .TermsOfServiceAgreement, .InfoAffirmation"
    }
  }
  
 * @author Dave
 *
 */

public class SignatureReader {

	Map<String,Object> map;
	
	@SuppressWarnings("unchecked")
	public SignatureReader(String json) {
		ObjectMapper mapper = new ObjectMapper();
		try {
			map = mapper.readValue(json, Map.class);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
	@SuppressWarnings("unchecked")
	public SignatureReader(Reader reader) {
		ObjectMapper mapper = new ObjectMapper();
		try {
			map = mapper.readValue(reader, Map.class);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
	@SuppressWarnings("unchecked")
	public CryptoSignature read() {
		
				String uuid = null;
				Iterator<String> iter = map.keySet().iterator();
				if(iter.hasNext()) {
					uuid = iter.next();
				}
				
				if(uuid == null) throw new RuntimeException("JSON Input looks invalid");

				Map<String, Object> sigData = (Map<String, Object>) map.get(uuid);
				SignatureAlgorithm sigAlg = SignatureAlgorithm.valueOf(
						String.valueOf(sigData.get("SignatureAlgorithm")));
				// common to all
				Date createdOn = TimeUtil.getISO8601FormatDate(String.valueOf(sigData.get("CreatedOn")));
				String signedWith = String.valueOf(sigData.get("SignedWith"));
				String signedBy = String.valueOf(sigData.get("SignedBy"));
				String digestAlg = String.valueOf(sigData.get("DigestAlgorithm"));
				SignatureMetadata meta = 
						new SignatureMetadata(uuid,createdOn,sigAlg,digestAlg,signedWith,signedBy);
				List<String> dataRefs = CryptoSignature.parseDataReferenceString(String.valueOf(sigData.get("DataRefs")));
				
				// specific to the encoding of each CryptoSignature subclass
				switch(sigAlg){
					case RSA: {
						String sval = String.valueOf(sigData.get("s"));
						RSASignature sig = new RSASignature(new ArmoredString(sval));
						return new RSACryptoSignature(meta,dataRefs,sig);
					}
					case ECDSA: {
						BigInteger r = new BigInteger(String.valueOf(sigData.get("r")), 16);
						BigInteger s = new BigInteger(String.valueOf(sigData.get("s")), 16);
						
						ECDSASignature sig = new ECDSASignature(r,s);
						return new ECDSACryptoSignature(meta,dataRefs,sig);
					}
					case ECKCDSA: {
						ArmoredString v = new ArmoredString(String.valueOf(sigData.get("v")));
						ArmoredString s = new ArmoredString(String.valueOf(sigData.get("s")));
						C2Signature sig = new C2Signature(v,s);
						return new C2CryptoSignature(meta,dataRefs,sig);
					}
					default: {
						throw new RuntimeException("Unknown SignatureAlgorithm: "+sigAlg);
					}
				}
		}

}
