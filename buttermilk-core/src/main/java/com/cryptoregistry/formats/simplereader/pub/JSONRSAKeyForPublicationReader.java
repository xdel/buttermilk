/*
 *  This file is part of Buttermilk
 *  Copyright 2011-2014 David R. Smith All Rights Reserved.
 *
 */
package com.cryptoregistry.formats.simplereader.pub;

import java.io.Reader;
import java.math.BigInteger;
import java.util.Date;
import java.util.Iterator;
import java.util.Map;

import com.cryptoregistry.formats.EncodingHint;
import com.cryptoregistry.formats.FormatUtil;
import com.cryptoregistry.formats.KeyFormat;
import com.cryptoregistry.formats.Mode;
import com.cryptoregistry.rsa.RSAKeyForPublication;
import com.cryptoregistry.rsa.RSAKeyMetadata;
import com.cryptoregistry.util.TimeUtil;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * <p>
 * JSONReader's design works on the premise the reader instance knows nothing about the key
 * materials it is reading; the file could contain 1 key or 100 and a lot of other stuff
 * besides. But sometimes you just need a very simple reader which assumes the 
 * program knows at design time the nature of the key to be read - i.e., the programmer knows
 * what kind of keys she is using and can rely on the type. 
 * </p>
 * 
 * <p>
 * While less general, this approach allows the programmer to avoid the process of testing 
 * the runtime object to find the type which was parsed using the "KeyMaterials" semantics. 
 * In other words, it is a simple, efficient, direct approach.  
 * </p>
 * 
 * <p>This class assumes you are reading a very simple key file with no associated signatures
 *  essentially like the below. It can read only the For Publication mode of an RSA Key.
 * </p>
 * 
 * <pre>
 
 For publication:
 
 

 </pre>
 * 
 * 
 * @author Dave
 * @see JSONFormatter
 * 
 */
public class JSONRSAKeyForPublicationReader {
	
	protected final ObjectMapper mapper;
	protected final Map<String,Object> map;
	 
	@SuppressWarnings("unchecked")
	public JSONRSAKeyForPublicationReader(Reader in) {
		mapper = new ObjectMapper();
		try {
			map = mapper.readValue(in, Map.class);
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}
	
	@SuppressWarnings("unchecked")
	public JSONRSAKeyForPublicationReader(String in) {
		mapper = new ObjectMapper();
		try {
			map = mapper.readValue(in, Map.class);
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}

	@SuppressWarnings("unchecked")
	public RSAKeyForPublication parse() {
		Iterator<String> iter = map.keySet().iterator();
		if (iter.hasNext()) {
			String distUUID = iter.next();
			Map<String, Object> inner = (Map<String, Object>) map.get(distUUID);
			if (distUUID.endsWith("-P")) {
				Date createdOn = TimeUtil.getISO8601FormatDate(String
						.valueOf(inner.get("CreatedOn")));
				
				EncodingHint enc = EncodingHint.valueOf(String.valueOf(inner.get("Encoding")));
				int strength = Integer.parseInt(String.valueOf(inner.get("Strength")));
				BigInteger Modulus = FormatUtil.unwrap(enc, String.valueOf(inner.get("Modulus")));
				BigInteger publicExponent = FormatUtil.unwrap(enc, String.valueOf(inner.get("PublicExponent")));

				RSAKeyMetadata meta = new RSAKeyMetadata(
						distUUID.substring(0, distUUID.length() - 2), 
						createdOn, 
						new KeyFormat(enc, Mode.REQUEST_FOR_PUBLICATION, null)
				);
				
				meta.setStrength(strength);

				return new RSAKeyForPublication(meta, Modulus,publicExponent);

			} else {
				throw new RuntimeException("unexpected Mode, needs to be For Publication");
			}
		} else {
			throw new RuntimeException("Count not find the uuid, fail");
		}
	}
}
