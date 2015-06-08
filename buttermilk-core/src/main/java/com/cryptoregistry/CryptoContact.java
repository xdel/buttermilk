/*
 *  This file is part of Buttermilk
 *  Copyright 2011-2014 David R. Smith All Rights Reserved.
 *
 */
package com.cryptoregistry;

import java.io.IOException;
import java.io.StringWriter;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;

import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.JsonGenerator;

/**
 * Backing for a contact record. 
 * 
 * @author Dave
 *
 */
public class CryptoContact {

	public static final int MAX_KEY_LENGTH = 64;
	public static final int MAX_VALUE_LENGTH = 255;
	
	protected final Map<String,String> map;
	public final String handle;
	
	public CryptoContact() {
		map = new LinkedHashMap<String,String>();
		handle = UUID.randomUUID().toString();
	}
	
	public CryptoContact(String handle) {
		map = new LinkedHashMap<String,String>();
		this.handle = handle;
	}
	
	/**
	 * Validates content values for length - security feature
	 *  
	 * @param handle
	 * @param contents
	 */
	public CryptoContact(String handle, Map<String,Object> contents) {
		map = new LinkedHashMap<String,String>();
		this.handle = handle;
		Iterator<String> iter = contents.keySet().iterator();
		while(iter.hasNext()){
			String key = iter.next();
			Object value = contents.get(key);
			String val = String.valueOf(value);
			if(key.length() > MAX_KEY_LENGTH) throw new RuntimeException("key too long");
			if(val.length() > MAX_VALUE_LENGTH) throw new RuntimeException("value too long");
			map.put(key, val);
		}
	}
	
	public Map<String,String> add(String key, String value){
		if(key.length() > MAX_KEY_LENGTH) throw new RuntimeException("key too long");
		if(value.length() > MAX_VALUE_LENGTH) throw new RuntimeException("value too long");
		map.put(key,value);
		return map;
	}
	
	public String get(String key){
		return map.get(key);
	}
	
	public Iterator<String> iterator() {
		return map.keySet().iterator();
	}

	public Map<String, String> getMap() {
		return map;
	}

	public String getHandle() {
		return handle;
	}
	
	/**
	 * Formats this contact record including the handle
	 * 
	 * @return
	 */
	public String formatJSON() {
		StringWriter writer = new StringWriter();
		JsonFactory f = new JsonFactory();
		JsonGenerator g = null;
		try {
			g = f.createGenerator(writer);
			g.writeStartObject();
			g.writeObjectFieldStart(getHandle());
			Iterator<String> inner = iterator();
			while(inner.hasNext()){
				String key = inner.next();
				if(key.equals("Handle")) continue;
				g.writeStringField(key, get(key));
			}
			g.writeEndObject();
		} catch (IOException x) {
			throw new RuntimeException(x);
		} finally {
			try {
				if (g != null)
					g.close();
			} catch (IOException e) {
				throw new RuntimeException(e);
			}
		}
			
		return writer.toString();
	}

}
