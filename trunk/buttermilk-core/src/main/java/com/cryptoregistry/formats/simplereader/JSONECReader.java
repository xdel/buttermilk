/*
 *  This file is part of Buttermilk
 *  Copyright 2011-2014 David R. Smith All Rights Reserved.
 *
 */
package com.cryptoregistry.formats.simplereader;

import java.io.File;
import java.io.Reader;
import java.util.Map;

import com.cryptoregistry.CryptoKeyWrapper;
import com.cryptoregistry.CryptoKeyWrapperImpl;
import com.cryptoregistry.ec.*;
import com.cryptoregistry.ec.ECKeyForPublication;
import com.cryptoregistry.formats.ECKeyFormatReader;
import com.cryptoregistry.passwords.Password;
import com.cryptoregistry.pbe.ArmoredPBEResult;
import com.cryptoregistry.pbe.PBEAlg;
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
 *  essentially like the below. It can read all three modes, unsecured, secured, and for publication. 
 *  To read a secured mode you must have provided the password.
 * </p>
 * 
 * @author Dave
 * @see JSONFormatter
 * 
 */
public class JSONECReader {
	
	protected final ObjectMapper mapper;
	protected final Map<String,Object> map;
	protected final Password password; // optional, set if you know the file to be read is in secure mode (-S). 
	
	/**
	 * Fails immediately if anything goes wrong reading the file or parsing
	 * @param path
	 */
	@SuppressWarnings("unchecked")
	public JSONECReader(File path) {
		
		password = null;
		mapper = new ObjectMapper();
		try {
			map = mapper.readValue(path, Map.class);
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}
	
	@SuppressWarnings("unchecked")
	public JSONECReader(Reader in) {
		
		password = null;
		mapper = new ObjectMapper();
		try {
			map = mapper.readValue(in, Map.class);
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}
	
	/**
	 * Use when we expect the file is secured (i.e., the key uses mode S).
	 * 
	 * @param file
	 * @param password
	 */
	@SuppressWarnings("unchecked")
	public JSONECReader(File path, Password password){

		this.password = password;
		mapper = new ObjectMapper();
		try {
			map = mapper.readValue(path, Map.class);
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}
	
	/**
	 * Use when we expect the file is secured (i.e., the key uses mode S).
	 * 
	 * @param file
	 * @param password
	 */
	@SuppressWarnings("unchecked")
	public JSONECReader(Reader in, Password password) {
		
		this.password = password;
		mapper = new ObjectMapper();
		try {
			map = mapper.readValue(in, Map.class);
		} catch (Exception e) {
			e.printStackTrace();
			throw new RuntimeException(e);
		}
	}

	/**
	 * One use only - password self-destructs after this call
	 * @return
	 */
	@SuppressWarnings("unchecked")
	public ECKeyForPublication parse() {
		// if password not passed in, assume we are in Unsecured form
		if(password == null) {
			ECKeyFormatReader reader = new ECKeyFormatReader(map);
			return reader.read();
		}else{
			// leverage the unlock method in the wrapper class
			// unchecked
			Map<String,Object> keysMap = (Map<String,Object>)map.get("Keys");
			// assume one key present - no checks on this
			String key = keysMap.keySet().iterator().next();
			final ArmoredPBEResult wrapped = PBEAlg.loadFrom((Map<String,Object>)keysMap.get(key));
			CryptoKeyWrapper wrapper = new CryptoKeyWrapperImpl(wrapped);
			wrapper.unlock(password);
			password.selfDestruct();
			return (ECKeyContents) wrapper.getKeyContents();
		}
	}
}
