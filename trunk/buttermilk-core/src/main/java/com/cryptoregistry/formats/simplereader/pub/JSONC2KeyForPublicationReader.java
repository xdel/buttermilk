/*
 *  This file is part of Buttermilk
 *  Copyright 2011-2014 David R. Smith All Rights Reserved.
 *
 */
package com.cryptoregistry.formats.simplereader.pub;

import java.io.Reader;
import java.util.Date;
import java.util.Iterator;
import java.util.Map;

import com.cryptoregistry.c2.key.C2KeyMetadata;
import com.cryptoregistry.c2.key.Curve25519KeyForPublication;
import com.cryptoregistry.c2.key.PublicKey;
import com.cryptoregistry.formats.EncodingHint;
import com.cryptoregistry.formats.KeyFormat;
import com.cryptoregistry.formats.Mode;
import com.cryptoregistry.util.ArmoredString;
import com.cryptoregistry.util.TimeUtil;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * Given a map of key data in unlocked condition, create a C2 style key from that
 * 
 * @author Dave
 *
 */
public class JSONC2KeyForPublicationReader {
	
	protected final ObjectMapper mapper;
	protected final Map<String,Object> map;
	 
	@SuppressWarnings("unchecked")
	public JSONC2KeyForPublicationReader(Reader in) {
		mapper = new ObjectMapper();
		try {
			map = mapper.readValue(in, Map.class);
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}
	
	@SuppressWarnings("unchecked")
	public JSONC2KeyForPublicationReader(String in) {
		mapper = new ObjectMapper();
		try {
			map = mapper.readValue(in, Map.class);
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}
	
	@SuppressWarnings("unchecked")
	public Curve25519KeyForPublication parse() {
		Iterator<String> iter = map.keySet().iterator();
		if(iter.hasNext()){
			String distUUID = iter.next();
			Map<String,Object> inner = (Map<String,Object>) map.get(distUUID);
			if(distUUID.endsWith("-P")){
			//	String keyAlgorithm = String.valueOf(inner.get("KeyAlgorithm"));
				Date createdOn = TimeUtil.getISO8601FormatDate(String.valueOf(inner.get("CreatedOn")));
				
				// at the moment these are always base64url
				EncodingHint enc =	EncodingHint.valueOf(String.valueOf(inner.get("Encoding")));
				if(enc != EncodingHint.Base64url) throw new RuntimeException("Unexpected encoding, needs to be Base64url");
				
				ArmoredString P = new ArmoredString(String.valueOf(inner.get("P")));
				
				
				C2KeyMetadata meta = new C2KeyMetadata(
						distUUID.substring(0,distUUID.length()-2),
						createdOn,
						new KeyFormat(enc,Mode.REQUEST_FOR_PUBLICATION,null)
				);
				
				PublicKey pKey = new PublicKey(P.decodeToBytes());
				
				return new Curve25519KeyForPublication(meta,pKey);
				
			}else{
				throw new RuntimeException("unexpected Mode, needs to be ForPublication");
			}
		}else{
			throw new RuntimeException("Count not find the uuid, fail");
		}
	}

}
