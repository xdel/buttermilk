/*
 *  This file is part of Buttermilk
 *  Copyright 2011-2014 David R. Smith All Rights Reserved.
 *
 */
package com.cryptoregistry.signature.builder;

import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.List;

import x.org.bouncycastle.crypto.Digest;
import x.org.bouncycastle.crypto.digests.SHA256Digest;

import com.cryptoregistry.SignatureAlgorithm;
import com.cryptoregistry.rsa.CryptoFactory;
import com.cryptoregistry.rsa.RSAKeyContents;
import com.cryptoregistry.signature.RSACryptoSignature;
import com.cryptoregistry.signature.SignatureMetadata;


/**<pre>
 * 
 * construct a signature using RSA. Process:
 * 
 * builder(registration handle, signer key contents, digest)
 * builder.update("handle:token0", bytes0)
 * builder.update("handle:token1", bytes1)
 * builder.update("handle:token2", bytes2)
 * RSACryptoSignature sigHolder = builder.build()
 * 
 * </pre>
 * @author Dave
 *
 */
public class RSASignatureBuilder  extends SignatureBuilder {

	final RSAKeyContents sKey;
	final Digest digest;
	final List<String> references;
	final String signedBy;
	final SignatureMetadata meta;
	
	public RSASignatureBuilder(String signedBy, RSAKeyContents sKey, Digest digest) {
		super();
		this.sKey = sKey;
		this.digest = digest;
		this.references=new ArrayList<String>();
		this.signedBy = signedBy;
		if(signedBy == null) throw new RuntimeException("Registration Handle cannot be null");
		
		meta = new SignatureMetadata(
				SignatureAlgorithm.RSA,
				digest.getAlgorithmName(),
				sKey.getMetadata().getHandle(),
				signedBy);
		update(meta.getHandle()+":SignedBy",signedBy);
		update(".SignedWith",sKey.getMetadata().getHandle());
		
	}
	
	/**
	 * By default this constructor updates SignedBy and SignedWith, so even with no other
	 * calls to update you get a meaningful signature out of build()
	 *  
	 * @param signedBy
	 * @param sKey
	 */
	public RSASignatureBuilder(String signedBy, RSAKeyContents sKey) {
		super();
		this.sKey = sKey;
		this.digest = new SHA256Digest();
		this.references=new ArrayList<String>();
		this.signedBy = signedBy;
		if(signedBy == null) throw new RuntimeException("Registration Handle cannot be null");
		meta = new SignatureMetadata(
				SignatureAlgorithm.RSA,
				digest.getAlgorithmName(),
				sKey.getMetadata().getHandle(),
				signedBy);
		update(meta.getHandle()+":SignedBy",signedBy);
		update(".SignedWith",sKey.getMetadata().getHandle());
	}
	
	public RSASignatureBuilder update(String label, String input){
		if(input == null) throw new RuntimeException("Input is null: "+label);
		references.add(label);
		byte [] bytes = input.getBytes(Charset.forName("UTF-8"));
		/*
		try {
			System.err.println("sign="+label+", "+Base64.encodeBytes(bytes, Base64.URL_SAFE));
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		*/
		digest.update(bytes, 0, bytes.length);
		return this;
	}
	
	public RSASignatureBuilder update(String label, byte[] bytes){
		if(bytes == null) throw new RuntimeException("Input is null: "+label);
		references.add(label);
		digest.update(bytes, 0, bytes.length);
		/*
		try {
			System.err.println("sign="+label+", "+Base64.encodeBytes(bytes, Base64.URL_SAFE));
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		*/
		return this;
	}
	
	public RSACryptoSignature build(){
		byte [] bytes = new byte[digest.getDigestSize()];
		digest.doFinal(bytes, 0);
		digest.reset();
		log(meta,bytes);
		RSACryptoSignature sig = CryptoFactory.INSTANCE.sign(meta, sKey, bytes);
		for(String ref: references) {
			sig.addDataReference(ref);
		}
		references.clear();
		return sig;
	}

}
