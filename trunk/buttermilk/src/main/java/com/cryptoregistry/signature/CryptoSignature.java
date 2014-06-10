/*
 *  This file is part of Buttermilk(TM) 
 *  Copyright 2013-2014 David R. Smith for cryptoregistry.com
 *
 */
package com.cryptoregistry.signature;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

/**
 * Base class for holder of a signature's data
 * 
 * @author Dave
 *
 */
public class CryptoSignature implements Serializable {

	protected static final long serialVersionUID = 1L;
	
	public final SignatureMetadata metadata;
	public final List<String> dataRefs;
	
	public CryptoSignature(SignatureMetadata metadata) {
		super();
		this.metadata = metadata;
		dataRefs = new ArrayList<String>();
	}

	public void addDataReference(String ref){
		dataRefs.add(ref);
	}

	public List<String> getDataRefs() {
		return dataRefs;
	}
	
	public SignatureData getSignatureData() {
		return null;
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

}
