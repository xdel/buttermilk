/*
 *  This file is part of Buttermilk
 *  Copyright 2011-2014 David R. Smith All Rights Reserved.
 *
 */
package com.cryptoregistry.signature;

import java.math.BigInteger;

public class ECDSASignature implements SignatureBytes {
	
	public final BigInteger r;
	public final BigInteger s;
	
	public ECDSASignature(BigInteger r, BigInteger s) {
		super();
		this.r = r;
		this.s = s;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((r == null) ? 0 : r.hashCode());
		result = prime * result + ((s == null) ? 0 : s.hashCode());
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
		ECDSASignature other = (ECDSASignature) obj;
		if (r == null) {
			if (other.r != null)
				return false;
		} else if (!r.equals(other.r))
			return false;
		if (s == null) {
			if (other.s != null)
				return false;
		} else if (!s.equals(other.s))
			return false;
		return true;
	}

	@Override
	public byte[] b1() {
		return r.toByteArray();
	}

	@Override
	public byte[] b2() {
		return s.toByteArray();
	}

	@Override
	public boolean hasTwoMembers() {
		return true;
	}

}
