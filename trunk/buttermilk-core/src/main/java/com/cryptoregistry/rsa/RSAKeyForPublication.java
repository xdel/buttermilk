/*
 *  This file is part of Buttermilk
 *  Copyright 2011-2014 David R. Smith All Rights Reserved.
 *
 */
package com.cryptoregistry.rsa;

import java.io.IOException;
import java.io.StringWriter;
import java.math.BigInteger;

import com.cryptoregistry.CryptoKey;
import com.cryptoregistry.CryptoKeyMetadata;
import com.cryptoregistry.Verifier;
import com.cryptoregistry.formats.FormatUtil;
import com.cryptoregistry.util.TimeUtil;
import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.JsonGenerator;

import x.org.bouncycastle.crypto.params.RSAKeyParameters;

public class RSAKeyForPublication  implements CryptoKey,Verifier {
	
	public final RSAKeyMetadata metadata;
	public final BigInteger  modulus;
	public final BigInteger  publicExponent;
	
	public RSAKeyForPublication(RSAKeyMetadata meta,
			BigInteger modulus, BigInteger publicExponent) {
		super();
		this.metadata = meta;
		this.modulus = modulus;
		this.publicExponent = publicExponent;
	}

	public final RSAKeyParameters getPublicKey() {
		return new RSAKeyParameters(false, modulus, publicExponent);
	}
	
	public final String toString() {
		return metadata.handle;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result
				+ ((metadata == null) ? 0 : metadata.hashCode());
		result = prime * result + ((modulus == null) ? 0 : modulus.hashCode());
		result = prime * result
				+ ((publicExponent == null) ? 0 : publicExponent.hashCode());
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
		RSAKeyForPublication other = (RSAKeyForPublication) obj;
		if (metadata == null) {
			if (other.metadata != null)
				return false;
		} else if (!metadata.equals(other.metadata))
			return false;
		if (modulus == null) {
			if (other.modulus != null)
				return false;
		} else if (!modulus.equals(other.modulus))
			return false;
		if (publicExponent == null) {
			if (other.publicExponent != null)
				return false;
		} else if (!publicExponent.equals(other.publicExponent))
			return false;
		return true;
	}

	@Override
	public CryptoKeyMetadata getMetadata() {
		return metadata;
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
			g.writeObjectFieldStart(metadata.getHandle()+"-P");
			g.writeStringField("KeyAlgorithm", "RSA");
			g.writeStringField("CreatedOn", TimeUtil.format(metadata.createdOn));
			g.writeStringField("Encoding", metadata.format.encodingHint.toString());
			g.writeStringField("Strength", String.valueOf(metadata.strength));
			g.writeStringField("Modulus", FormatUtil.wrap(metadata.format.encodingHint, modulus));
			g.writeStringField("PublicExponent", FormatUtil.wrap(metadata.format.encodingHint, publicExponent));
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
		return cloneForPublication();
	}
	
	public RSAKeyForPublication cloneForPublication(){
		RSAKeyMetadata meta = this.metadata.cloneForPublication();
		return new RSAKeyForPublication(meta,this.modulus,this.publicExponent);
	}
	
	
}
