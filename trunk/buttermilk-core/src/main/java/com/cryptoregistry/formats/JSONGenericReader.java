package com.cryptoregistry.formats;

import java.io.File;
import java.io.Reader;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import com.cryptoregistry.MapData;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * In some cases we need just to get the JSON data into Maps, we do not need to load it into value objects.
 * 
 * @author Dave
 *
 */

public class JSONGenericReader {
	
	public final Map<String,Object> map;

	@SuppressWarnings("unchecked")
	public JSONGenericReader(File path) {
		ObjectMapper mapper = new ObjectMapper();
		try {
			map = mapper.readValue(path, Map.class);
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}
	
	@SuppressWarnings("unchecked")
	public JSONGenericReader(Reader in) {
		ObjectMapper mapper = new ObjectMapper();
		try {
			map = mapper.readValue(in, Map.class);
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}
	
	public String version() {
		return String.valueOf(map.get("Version"));
	}
	
	public String regHandle() {
		return String.valueOf(map.get("RegHandle"));
	}
	
	public String email() {
		return String.valueOf(map.get("Email"));
	}
	
	@SuppressWarnings("unchecked")
	public List<MapData> keys() {
		List<MapData> list = new ArrayList<MapData>();
		Map<String, Object> uuids = (Map<String, Object>) map.get("Keys");
		Iterator<String> iter = uuids.keySet().iterator();
		while(iter.hasNext()) {
			String distinguishedKey = iter.next();
			Map<String, Object> keyData = (Map<String, Object>) uuids.get(distinguishedKey);
			MapData md = new MapData(distinguishedKey);
			Iterator<String> inner = keyData.keySet().iterator();
			while(inner.hasNext()){
				String key = inner.next();
				md.put(key, String.valueOf(keyData.get(key)));
			}
			list.add(md);
		}
		return list;
	}
	
	@SuppressWarnings("unchecked")
	public List<MapData> contacts() {
		List<MapData> list = new ArrayList<MapData>();
		Map<String, Object> uuids = (Map<String, Object>) map.get("Contacts");
		Iterator<String> iter = uuids.keySet().iterator();
		while(iter.hasNext()) {
			String id = iter.next();
			Map<String, Object> keyData = (Map<String, Object>) uuids.get(id);
			MapData md = new MapData(id);
			Iterator<String> inner = keyData.keySet().iterator();
			while(inner.hasNext()){
				String key = inner.next();
				md.put(key, String.valueOf(keyData.get(key)));
			}
			list.add(md);
		}
		return list;
	}
	
	@SuppressWarnings("unchecked")
	public List<MapData> signatures() {
		List<MapData> list = new ArrayList<MapData>();
		Map<String, Object> uuids = (Map<String, Object>) map.get("Signatures");
		Iterator<String> iter = uuids.keySet().iterator();
		while(iter.hasNext()) {
			String id = iter.next();
			Map<String, Object> keyData = (Map<String, Object>) uuids.get(id);
			MapData md = new MapData(id);
			Iterator<String> inner = keyData.keySet().iterator();
			while(inner.hasNext()){
				String key = inner.next();
				md.put(key, String.valueOf(keyData.get(key)));
			}
			list.add(md);
		}
		return list;
	}
	
	@SuppressWarnings("unchecked")
	public List<MapData> local() {
		List<MapData> list = new ArrayList<MapData>();
		Map<String, Object> data = (Map<String, Object>) map.get("Data");
		Map<String, Object> uuids = (Map<String, Object>) data.get("Local");
		Iterator<String> iter = uuids.keySet().iterator();
		while(iter.hasNext()) {
			String id = iter.next();
			Map<String, Object> keyData = (Map<String, Object>) uuids.get(id);
			MapData md = new MapData(id);
			Iterator<String> inner = keyData.keySet().iterator();
			while(inner.hasNext()){
				String key = inner.next();
				md.put(key, String.valueOf(keyData.get(key)));
			}
			list.add(md);
		}
		return list;
	}

}
