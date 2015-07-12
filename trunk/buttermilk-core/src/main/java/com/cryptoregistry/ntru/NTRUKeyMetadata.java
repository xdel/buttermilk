/*
 *  This file is part of Buttermilk
 *  Copyright 2011-2014 David R. Smith All Rights Reserved.
 *
 */
package com.cryptoregistry.ntru;

import java.util.Date;
import java.util.UUID;

import com.cryptoregistry.CryptoKeyMetadata;
import com.cryptoregistry.KeyGenerationAlgorithm;
import com.cryptoregistry.formats.EncodingHint;
import com.cryptoregistry.formats.KeyFormat;
import com.cryptoregistry.formats.Mode;
import com.cryptoregistry.pbe.PBEParams;
import com.cryptoregistry.pbe.PBEParamsFactory;

public class NTRUKeyMetadata implements CryptoKeyMetadata {

	public final String handle;
	public final Date createdOn;
	public final KeyFormat format;

	public NTRUKeyMetadata(String handle, Date createdOn, KeyFormat format) {
		super();
		this.handle = handle;
		this.createdOn = createdOn;
		this.format = format;
	}
	
	/**
	 * Returns a default handle, createOn, and KeyFormat for base64Encode, Mode.OPEN
	 * @return
	 */
	public static NTRUKeyMetadata createDefault() {
		return new NTRUKeyMetadata(UUID.randomUUID().toString(), new Date(),new KeyFormat(EncodingHint.NoEncoding,Mode.UNSECURED,null));
	}
	
	public static NTRUKeyMetadata createForPublication() {
		return new NTRUKeyMetadata(UUID.randomUUID().toString(), new Date(),new KeyFormat(EncodingHint.NoEncoding,Mode.REQUEST_FOR_PUBLICATION,null));
	}
	
	public static NTRUKeyMetadata createSecureDefault(char[]passwordChars) {
		return new NTRUKeyMetadata(UUID.randomUUID().toString(), new Date(),
				new KeyFormat(EncodingHint.NoEncoding, 
						Mode.REQUEST_SECURE, 
						PBEParamsFactory.INSTANCE.createPBKDF2Params(passwordChars)));
	}
	
	public static NTRUKeyMetadata createSecureScrypt(char[]password) {
		return new NTRUKeyMetadata(UUID.randomUUID().toString(), new Date(),
				new KeyFormat(EncodingHint.NoEncoding,
						Mode.REQUEST_SECURE, 
						PBEParamsFactory.INSTANCE.createScryptParams(password)));
	}
	
	public static NTRUKeyMetadata createSecure(PBEParams params) {
		return new NTRUKeyMetadata(UUID.randomUUID().toString(), new Date(),
				new KeyFormat(EncodingHint.NoEncoding,
						Mode.REQUEST_SECURE, 
						params));
	}

	@Override
	public String getHandle() {
		return handle;
	}
	
	public String getDistinguishedHandle() {
		return handle+"-"+format.mode.code;
	}

	@Override
	public KeyGenerationAlgorithm getKeyAlgorithm() {
		return KeyGenerationAlgorithm.NTRU;
	}

	@Override
	public Date getCreatedOn() {
		return createdOn;
	}

	@Override
	public KeyFormat getFormat() {
		return format;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result
				+ ((createdOn == null) ? 0 : createdOn.hashCode());
		result = prime * result + ((format == null) ? 0 : format.hashCode());
		result = prime * result + ((handle == null) ? 0 : handle.hashCode());
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
		NTRUKeyMetadata other = (NTRUKeyMetadata) obj;
		if (createdOn == null) {
			if (other.createdOn != null)
				return false;
		} else if (!createdOn.equals(other.createdOn))
			return false;
		if (format == null) {
			if (other.format != null)
				return false;
		} else if (!format.equals(other.format))
			return false;
		if (handle == null) {
			if (other.handle != null)
				return false;
		} else if (!handle.equals(other.handle))
			return false;
		return true;
	}
	
	public NTRUKeyMetadata cloneForPublication() {
		return new NTRUKeyMetadata(handle, createdOn,new KeyFormat(EncodingHint.NoEncoding,Mode.REQUEST_FOR_PUBLICATION, null));
	}

	@Override
	public String toString() {
		return "NTRUKeyMetadata [handle=" + handle + ", createdOn=" + createdOn
				+ ", format=" + format + "]";
	}

}
