package com.cryptoregistry.ntru;

import java.util.Date;

import com.cryptoregistry.CryptoKeyMetadata;
import com.cryptoregistry.KeyGenerationAlgorithm;
import com.cryptoregistry.formats.KeyFormat;
import com.cryptoregistry.util.ArmoredCompressedString;
import com.cryptoregistry.util.ArrayUtil;

import x.org.bouncycastle.pqc.crypto.ntru.NTRUEncryptionParameters;
import x.org.bouncycastle.pqc.crypto.ntru.NTRUEncryptionPrivateKeyParameters;
import x.org.bouncycastle.pqc.math.ntru.polynomial.DenseTernaryPolynomial;
import x.org.bouncycastle.pqc.math.ntru.polynomial.IntegerPolynomial;
import x.org.bouncycastle.pqc.math.ntru.polynomial.Polynomial;
import x.org.bouncycastle.pqc.math.ntru.polynomial.ProductFormPolynomial;
import x.org.bouncycastle.pqc.math.ntru.polynomial.SparseTernaryPolynomial;

public class NTRUKeyContents extends NTRUKeyForPublication implements CryptoKeyMetadata{
	
	public final Polynomial t;
	public final IntegerPolynomial fp;

	public NTRUKeyContents(NTRUEncryptionParameters params, 
			IntegerPolynomial h, Polynomial t, IntegerPolynomial fp) {
		super(params, h);
		this.t = t;
		this.fp = fp;
	}
	
	public NTRUKeyContents(NTRUNamedParameters e, 
			IntegerPolynomial h, Polynomial t, IntegerPolynomial fp) {
		super(e, h);
		this.t = t;
		this.fp = fp;
	}

	public NTRUKeyContents(NTRUKeyMetadata metadata, 
			NTRUEncryptionParameters params, IntegerPolynomial h,
			Polynomial t, IntegerPolynomial fp) {
		super(metadata, params, h);
		this.t = t;
		this.fp = fp;
	}
	
	public NTRUKeyContents(NTRUKeyMetadata metadata, 
			NTRUNamedParameters e, IntegerPolynomial h,
			Polynomial t, IntegerPolynomial fp) {
		super(metadata, e, h);
		this.t = t;
		this.fp = fp;
	}

	public NTRUEncryptionPrivateKeyParameters getPrivateKey() {
		return new NTRUEncryptionPrivateKeyParameters(h,t,fp,params);
	}
	
	public ArmoredCompressedString wrappedFp() {
		return ArrayUtil.wrapIntArray(fp.coeffs);
	}
	
	public Object wrappedT() {
		if(t instanceof DenseTernaryPolynomial) {
			DenseTernaryPolynomial poly = (DenseTernaryPolynomial) t;
			return ArrayUtil.wrapIntArray(poly.coeffs);
		}else if(t instanceof SparseTernaryPolynomial) {
			SparseTernaryPolynomial poly = (SparseTernaryPolynomial) t;
			return ArrayUtil.wrapIntArray(poly.getCoeffs());
		}else if(t instanceof ProductFormPolynomial) {
			ProductFormPolynomial poly = (ProductFormPolynomial) t;
			SparseTernaryPolynomial []array = poly.getData();
			ArmoredCompressedString [] wrapper = new ArmoredCompressedString[3];
			wrapper[0] = ArrayUtil.wrapIntArray(array[0].getCoeffs());
			wrapper[1] = ArrayUtil.wrapIntArray(array[1].getCoeffs());
			wrapper[2] = ArrayUtil.wrapIntArray(array[2].getCoeffs());
			return wrapper;
		}
		
		throw new RuntimeException("Sorry, don't know how to create a wrapper which is not a DenseTernary, SparseTernary, or ProductForm Polynomial");
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = super.hashCode();
		result = prime * result + ((fp == null) ? 0 : fp.hashCode());
		result = prime * result + ((t == null) ? 0 : t.hashCode());
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (!super.equals(obj))
			return false;
		if (getClass() != obj.getClass())
			return false;
		NTRUKeyContents other = (NTRUKeyContents) obj;
		if (fp == null) {
			if (other.fp != null)
				return false;
		} else if (!fp.equals(other.fp))
			return false;
		if (t == null) {
			if (other.t != null)
				return false;
		} else if (!t.equals(other.t))
			return false;
		return true;
	}

	@Override
	public String getHandle() {
		return metadata.getHandle();
	}

	@Override
	public KeyGenerationAlgorithm getKeyAlgorithm() {
		return KeyGenerationAlgorithm.NTRU;
	}

	@Override
	public Date getCreatedOn() {
		return metadata.getCreatedOn();
	}

	@Override
	public KeyFormat getFormat() {
		return metadata.getFormat();
	}
	
	@Override
	public String toString() {
		return "NTRUKeyContents [t=" + t + ", fp=" + fp + "h="+ h+"]";
	}

}
