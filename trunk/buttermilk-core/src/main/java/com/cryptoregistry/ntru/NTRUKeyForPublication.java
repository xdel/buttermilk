/*
 *  This file is part of Buttermilk
 *  Copyright 2011-2014 David R. Smith All Rights Reserved.
 *
 */
package com.cryptoregistry.ntru;

import java.io.IOException;
import java.io.StringWriter;

import com.cryptoregistry.CryptoKey;
import com.cryptoregistry.CryptoKeyMetadata;
import com.cryptoregistry.KeyGenerationAlgorithm;
import com.cryptoregistry.Verifier;
import com.cryptoregistry.formats.NTRUParametersFormatter;
import com.cryptoregistry.util.ArmoredCompressedString;
import com.cryptoregistry.util.ArrayUtil;
import com.cryptoregistry.util.TimeUtil;
import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.JsonGenerator;

import x.org.bouncycastle.pqc.crypto.ntru.NTRUEncryptionParameters;
import x.org.bouncycastle.pqc.crypto.ntru.NTRUEncryptionPublicKeyParameters;
import x.org.bouncycastle.pqc.math.ntru.polynomial.IntegerPolynomial;

/**
 * When parameterName is defined, we can format this using our internal definitions (NTRUNamedParams)
 * 
 * @author Dave
 *
 */
public class NTRUKeyForPublication implements CryptoKey,Verifier {

	public final NTRUKeyMetadata metadata;
	public final NTRUEncryptionParameters params; 
	public final NTRUNamedParameters parameterEnum; // may be null
	public final IntegerPolynomial h;
	
	public NTRUKeyForPublication(NTRUEncryptionParameters params, IntegerPolynomial h) {
		metadata = NTRUKeyMetadata.createDefault();
		this.params = params;
		this.parameterEnum = null;
		this.h = h;
	}
	
	public NTRUKeyForPublication(NTRUKeyMetadata metadata, NTRUEncryptionParameters params, IntegerPolynomial h) {
		this.metadata = metadata;
		this.params = params;
		this.parameterEnum = null;
		this.h = h;
	}
	
	public NTRUKeyForPublication(NTRUNamedParameters e, IntegerPolynomial h) {
		metadata = NTRUKeyMetadata.createDefault();
		this.params = e.getParameters();
		this.parameterEnum = e;
		this.h = h;
	}
	
	public NTRUKeyForPublication(NTRUKeyMetadata metadata, NTRUNamedParameters e, IntegerPolynomial h) {
		this.metadata = metadata;
		this.params = e.getParameters();
		this.parameterEnum = e;
		this.h = h;
	}
	
	public NTRUEncryptionPublicKeyParameters getPublicKey() {
		return new NTRUEncryptionPublicKeyParameters(h,params);
	}
	
	public String getDistinguishedHandle() {
		return metadata.handle+"-"+metadata.format.mode.code;
	}
	
	public ArmoredCompressedString wrappedH() {
		return ArrayUtil.wrapAndCompressIntArray(h.coeffs);
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((h == null) ? 0 : h.hashCode());
		result = prime * result
				+ ((metadata == null) ? 0 : metadata.hashCode());
		result = prime * result + ((params == null) ? 0 : params.hashCode());
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
		NTRUKeyForPublication other = (NTRUKeyForPublication) obj;
		if (h == null) {
			if (other.h != null)
				return false;
		} else if (!h.equals(other.h))
			return false;
		if (metadata == null) {
			if (other.metadata != null)
				return false;
		} else if (!metadata.equals(other.metadata))
			return false;
		if (params == null) {
			if (other.params != null)
				return false;
		} else if (!params.equals(other.params))
			return false;
		return true;
	}

	@Override
	public String toString() {
		return "NTRUKeyForPublication [metadata=" + metadata + ", params="
				+ params + ", h=" + h + "]";
	}

	@Override
	public CryptoKeyMetadata getMetadata() {
		return metadata;
	}
	
	public boolean hasNamedParam(){
		if(this.parameterEnum!=null){
			return true;
		}
		return false;
	}

	@Override
	public String formatJSON() {
		StringWriter writer = new StringWriter();
		JsonFactory f = new JsonFactory();
		JsonGenerator g = null;
		try {
			g = f.createGenerator(writer);
			g.useDefaultPrettyPrinter();
			g.writeStartObject();
			g.writeObjectFieldStart(metadata.handle+"-P");
			g.writeStringField("KeyAlgorithm", KeyGenerationAlgorithm.NTRU.toString());
			g.writeStringField("CreatedOn", TimeUtil.format(metadata.createdOn));
			//g.writeStringField("Encoding", enc.toString());
			
			g.writeStringField("h", wrappedH().toString());
			
			NTRUParametersFormatter pFormat = null;
			if(parameterEnum == null) pFormat = new NTRUParametersFormatter(params);
			else pFormat = new NTRUParametersFormatter(parameterEnum);
			pFormat.format(g, writer);
			
			g.writeEndObject();
			
		} catch (IOException e) {
			e.printStackTrace();
		} finally {
			try {
				g.close();
			} catch (IOException e) {
				throw new RuntimeException(e);
			}
		}

		return writer.toString();
	}

	@Override
	public CryptoKey keyForPublication() {
		return new NTRUKeyForPublication(metadata,params,h);
	}

}
