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

public class MapData {

	public final String uuid;
	public final Map<String,String> data;
	
	public MapData() {
		uuid = UUID.randomUUID().toString();
		data = new LinkedHashMap<String,String>();
	}
	
	public MapData(String uuid) {
		this.uuid = uuid;
		data = new LinkedHashMap<String,String>();
	}
	
	public MapData(String uuid, Map<String,String> in) {
		this.uuid = uuid;
		data = new LinkedHashMap<String,String>();
		Iterator<String> keys = in.keySet().iterator();
		while(keys.hasNext()){
			String key = keys.next();
			String value = String.valueOf(in.get(key));
			data.put(key, value);
		}
	}
	
	public void put(String key, String value){
		data.put(key,value);
	}
	
	public String get(String key){
		return data.get(key);
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((data == null) ? 0 : data.hashCode());
		result = prime * result + ((uuid == null) ? 0 : uuid.hashCode());
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
		MapData other = (MapData) obj;
		if (data == null) {
			if (other.data != null)
				return false;
		} else if (!data.equals(other.data))
			return false;
		if (uuid == null) {
			if (other.uuid != null)
				return false;
		} else if (!uuid.equals(other.uuid))
			return false;
		return true;
	}

	@Override
	public String toString() {
		return "MapData [uuid=" + uuid + ", data=" + data + "]";
	}
	
	/**
	 * Output something like {"70f85718-63c9-473e-9cb0-2ba61b874a00-P":{"KeyAlgorithm":"EC",...}}
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
			g.writeObjectFieldStart(uuid);
			Iterator<String> inner = data.keySet().iterator();
			while(inner.hasNext()){
				String key = inner.next();
				if(key.equals("Handle")) continue;
				g.writeStringField(key, data.get(key));
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
