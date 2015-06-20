/*
 *  This file is part of Buttermilk(TM) 
 *  Copyright 2013-2014 David R. Smith for cryptoregistry.com
 *
 */
package com.cryptoregistry.signature;

import java.io.IOException;
import java.io.Serializable;
import java.io.Writer;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import x.org.bouncycastle.crypto.Digest;
import x.org.bouncycastle.crypto.digests.SHA1Digest;
import x.org.bouncycastle.crypto.digests.SHA256Digest;
import x.org.bouncycastle.crypto.digests.SHA512Digest;

import com.fasterxml.jackson.core.JsonGenerationException;
import com.fasterxml.jackson.core.JsonGenerator;

/**
 * Base class for holder of a signature and associated references to do verification
 * 
 * @author Dave
 *
 */
public abstract class CryptoSignature implements Serializable, CanFormatSignatureData {

	protected static final long serialVersionUID = 1L;
	
	public final SignatureMetadata metadata;
	public final List<String> dataRefs;
	
	public CryptoSignature(SignatureMetadata metadata) {
		super();
		this.metadata = metadata;
		dataRefs = new ArrayList<String>();
	}
	
	public CryptoSignature(SignatureMetadata metadata, List<String> refs) {
		super();
		this.metadata = metadata;
		dataRefs = refs;
	}
	
	public void addDataReference(String ref){
		dataRefs.add(ref);
	}

	public List<String> getDataRefs() {
		return dataRefs;
	}

	public String getHandle() {
		return metadata.getHandle();
	}

	public Date getCreatedOn() {
		return metadata.getCreatedOn();
	}

	public String getSignedWith() {
		return metadata.getSignedWith();
	}

	public String getSignedBy() {
		return metadata.getSignedBy();
	}
	
	public String getSigAlg() {
		return metadata.getSigAlg().toString();
	}
	
	public String getDigestAlg() {
		return metadata.digestAlg;
	}
	
	/**
	 * Some common ones
	 * 
	 * @return
	 */
	public Digest getDigestInstance() {
		switch(metadata.digestAlg){
			case "SHA1": return new SHA1Digest();
			case "SHA-1": return new SHA1Digest();
			case "SHA256": return new SHA256Digest();
			case "SHA-256": return new SHA256Digest();
			case "SHA512": return new SHA512Digest();
			case "SHA-512": return new SHA512Digest();
			
			default: throw new RuntimeException("Unknown Digest algorithm: "+metadata.digestAlg);
		}
	}

	@Override
	public String toString() {
		return "CryptoSignature [getHandle()=" + getHandle() + "]";
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result
				+ ((dataRefs == null) ? 0 : dataRefs.hashCode());
		result = prime * result
				+ ((metadata == null) ? 0 : metadata.hashCode());
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (getClass() != obj.getClass())
			return false;
		CryptoSignature other = (CryptoSignature) obj;
		if (dataRefs == null) {
			if (other.dataRefs != null)
				return false;
		} else if (!dataRefs.equals(other.dataRefs))
			return false;
		if (metadata == null) {
			if (other.metadata != null)
				return false;
		} else if (!metadata.equals(other.metadata))
			return false;
		return true;
	}

	/**
	 * implement these two methods in subclasses, these are bits which are different in each key
	 */

	public abstract void formatSignaturePrimitivesJSON(JsonGenerator g, Writer writer)
			throws JsonGenerationException, IOException;
	
	public abstract SignatureBytes signatureBytes();
	
	
	/**
	 * Return a String representation of the dataRefs (in comma delimited form)
	 * @return
	 */
	public static String getDataReferenceString(CryptoSignature sig) {
		StringBuffer buf = new StringBuffer();
		int count = 0;
		for(String part: sig.dataRefs){
			buf.append(part);
			if(count<sig.dataRefs.size()-1) buf.append(", ");
			count++;
		}
		return buf.toString();
	}
	
	/**
	 * Return a List parsed from what is generated in the above method
	 * 
	 * @param in
	 * @return
	 */
	public static List<String> parseDataReferenceString(String in) {
		List<String> list = new ArrayList<String>();
		String [] parts = in.split("\\,");
		for(String item: parts){
			list.add(item.trim());
		}
		return list;
	}

}

