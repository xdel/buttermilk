/*
 *  This file is part of Buttermilk
 *  Copyright 2011-2014 David R. Smith All Rights Reserved.
 *
 */
package com.cryptoregistry.formats;

import com.cryptoregistry.pbe.PBEParams;
import com.cryptoregistry.pbe.PBEParamsFactory;

/**
 * Encapsulate various modes for formatting. pbeParams is here to pass into the formatter if encryption of the key is requested
 * 
 * @author Dave
 *
 */
public class KeyFormat {

	public final EncodingHint encodingHint;
	public final Mode mode;
	public final PBEParams pbeParams;
	
	public KeyFormat(EncodingHint hint, Mode mode, PBEParams params){
		encodingHint = hint;
		this.mode = mode;
		this.pbeParams = params;
	}
	
	public static KeyFormat unsecured() {
		return new KeyFormat(EncodingHint.Base64url,Mode.UNSECURED,null);
	}
	
	public static KeyFormat forPublication() {
		return new KeyFormat(EncodingHint.Base64url,Mode.REQUEST_FOR_PUBLICATION,null);
	}
	
	public static KeyFormat securedPBKDF2(char [] passwordChars) {
		return new KeyFormat(EncodingHint.Base64url,Mode.REQUEST_SECURE,PBEParamsFactory.INSTANCE.createPBKDF2Params(passwordChars));
	}
	
	public static KeyFormat securedPBKDF2(int iterations, char [] passwordChars) {
		return new KeyFormat(EncodingHint.Base64url,Mode.REQUEST_SECURE,PBEParamsFactory.INSTANCE.createPBKDF2Params(iterations, passwordChars));
	}
	
	public static KeyFormat securedSCRYPT(char [] passwordChars) {
		return new KeyFormat(EncodingHint.Base64url,Mode.REQUEST_SECURE,PBEParamsFactory.INSTANCE.createScryptParams(passwordChars));
	}
	
	public static KeyFormat securedSCRYPT(int cpuCost, int parallelization, char [] passwordChars) {
		return new KeyFormat(EncodingHint.Base64url,Mode.REQUEST_SECURE,
				PBEParamsFactory.INSTANCE.createScryptParams(cpuCost,parallelization, passwordChars));
	}
	
	public KeyFormat clone() {
		PBEParams pbe = null;
		if(this.pbeParams != null){
			pbe = this.pbeParams.clone();
		}
		KeyFormat f = new KeyFormat(this.encodingHint, this.mode, pbe);
		return f;
	}

	@Override
	public String toString() {
		return "KeyFormat [encoding=" + encodingHint + ", mode=" + mode
				+ ", pbeParams=" + pbeParams + "]";
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result
				+ ((encodingHint == null) ? 0 : encodingHint.hashCode());
		result = prime * result + ((mode == null) ? 0 : mode.hashCode());
		result = prime * result
				+ ((pbeParams == null) ? 0 : pbeParams.hashCode());
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
		KeyFormat other = (KeyFormat) obj;
		if (encodingHint != other.encodingHint)
			return false;
		if (mode != other.mode)
			return false;
		if (pbeParams == null) {
			if (other.pbeParams != null)
				return false;
		} else if (!pbeParams.equals(other.pbeParams))
			return false;
		return true;
	}

}
