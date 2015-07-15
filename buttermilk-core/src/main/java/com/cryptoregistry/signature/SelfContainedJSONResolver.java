package com.cryptoregistry.signature;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import net.iharder.Base64;

import com.cryptoregistry.FileURLResolver;
import com.cryptoregistry.HTTPURLResolver;
import com.cryptoregistry.MapData;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * This is for the case where all the references are within the context of a
 * single registration JSON file (or similar)
 * 
 * @author Dave
 *
 */
public class SelfContainedJSONResolver implements SignatureReferenceResolver {

	protected final Map<String, Object> objectGraph;
	protected final Map<String, String> cache;

	private boolean debugMode;

	@SuppressWarnings("unchecked")
	public SelfContainedJSONResolver(InputStream in) {
		cache = new HashMap<String, String>();
		ObjectMapper mapper = new ObjectMapper();
		try {
			objectGraph = mapper.readValue(in, Map.class);
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}

	@SuppressWarnings("unchecked")
	public SelfContainedJSONResolver(String json) {
		cache = new HashMap<String, String>();
		ObjectMapper mapper = new ObjectMapper();
		try {
			objectGraph = mapper.readValue(json, Map.class);
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}

	public SelfContainedJSONResolver(Map<String, Object> map) {
		cache = new HashMap<String, String>();
		this.objectGraph = map;
	}

	public void walk() {
		collect(objectGraph);
		if(debugMode) {
			System.err.println("Loaded Cache:"+cache);
		}
	}

	/**
	 * For debugging, mainly
	 * 
	 * @param ref
	 * @return
	 * @throws RefNotFoundException
	 */
	public String resolve(String ref) throws RefNotFoundException {
		String normalized = preprocess(ref.trim());
		String out = cache.get(normalized);
		if (out == null)
			throw new RefNotFoundException("Could not find " + normalized);
		return out;
	}

	@Override
	/**
	 * implement SignatureReferenceResolver 
	 */
	public void resolve(String ref, ByteArrayOutputStream collector)
			throws RefNotFoundException {
		String normalized = preprocess(ref.trim());
		String out = cache.get(normalized);
		if (out == null)
			throw new RefNotFoundException("Could not find " + normalized);
		try {
			collector.write(out.getBytes("UTF-8"));
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	/**
	 * For debugging
	 * 
	 * @param refs
	 * @return
	 * @throws RefNotFoundException
	 */
	public List<String> resolve(List<String> refs) throws RefNotFoundException {
		List<String> result = new ArrayList<String>();
		for (String ref : refs) {
			String normalized = preprocess(ref.trim());
			String out = cache.get(normalized);
			if (out == null)
				throw new RefNotFoundException("Could not find " + normalized);
			result.add(out);
		}
		return result;
	}

	/**
	 * implement SignatureReferenceResolver
	 */
	@Override
	public void resolve(List<String> refs, ByteArrayOutputStream collector)
			throws RefNotFoundException {
		for (String ref : refs) {
			String normalized = preprocess(ref.trim());
			String out = cache.get(normalized);
			if (out == null)
				throw new RefNotFoundException("Could not find " + normalized);
			try {
				byte[] b = out.getBytes(Charset.forName("UTF-8"));
				collector.write(b);
				if (debugMode) {
					try {
						System.err.println("resolve=" + ref + ", "
								+ Base64.encodeBytes(b, Base64.URL_SAFE));
					} catch (IOException e) {
						e.printStackTrace();
					}
				}

			} catch (Exception e) {
				e.printStackTrace();
			}
		}

		if (debugMode) {
			System.err.println("collector has acquired " + collector.size()
					+ " bytes");
		}

	}

	private String uuid;

	/**
	 * Normalize the ref if required. The ref may have the following forms:
	 * 
	 * uuid:tokenName uuid(-(U|S|P)):tokenName .tokenName
	 * 
	 * Where the extended form indicates the mode and dot form is an
	 * abbreviation of the first or second case
	 * 
	 * preprocess normalizes the ref to be in all cases of the form
	 * uuid:tokenName
	 * 
	 * @param ref
	 * @return
	 */

	public String preprocess(String ref) {

		if (ref.startsWith(".")) {
			// impossible in the full uuid form, so must be abbreviated form
			StringBuffer buf = new StringBuffer();
			buf.append(uuid);
			buf.append(":");
			buf.append(ref.substring(1, ref.length()));
			return buf.toString();
		}

		String token = "";
		if (ref.contains(":")) {
			String[] parts = ref.split("\\:");
			if (parts[0].endsWith("-P") || parts[0].endsWith("-U")
					|| parts[0].endsWith("-S")) {
				uuid = parts[0].substring(0, parts[0].length() - 2);
			} else
				uuid = parts[0];
			token = parts[1];
		}
		StringBuffer buf = new StringBuffer(uuid);
		buf.append(":");
		buf.append(token);
		return buf.toString();

	}

	/**
	 * Walk the object graph, collecting the current uuid:reference and
	 * corresponding value along the way
	 * 
	 * @param map
	 * @param ref
	 * @return
	 */
	@SuppressWarnings({ "unchecked", "rawtypes" })
	void collect(Map map) {

		Iterator<String> iter = map.keySet().iterator();
		while (iter.hasNext()) {
			String key = iter.next();

			switch (key) {
			case "Keys": {
				Map inner = (Map) map.get(key);
				collect(inner);
				break;
			}
			case "Contacts": {
				Map inner = (Map) map.get(key);
				collect(inner);
				break;
			}
			case "Signatures": {
				Map inner = (Map) map.get(key);
				collect(inner);
				break;
			}
			case "Local": {
				Map inner = (Map) map.get(key);
				collect(inner);
				break;
			}
			case "Remote": {
				// the Remote data is a list of URLS
				List<String> inner = (List<String>) map.get(key);
				for (Object url : inner) {
					String item = String.valueOf(url);
					// what is the URL scheme on the list item - we support 2 
					final String scheme = item.substring(0, 4).toUpperCase();
					switch (scheme) {
					case "HTTP": {
						HTTPURLResolver resolver = new HTTPURLResolver(item);
						List<MapData> mapData = resolver.resolve();
						for (MapData ld : mapData) {
							collect(ld.data);
						}
						break;
					}
					case "FILE": {
						FileURLResolver resolver = new FileURLResolver(item);
						List<MapData> mapData = resolver.resolve();
						for (MapData ld : mapData) {
							collect(ld.data);
						}
						break;
					}
					default: {
						throw new RuntimeException(
								"don't handle this url scheme: " + scheme);
					}
					}
				}
				break;
			}
			case "Data": {
				Map inner = (Map) map.get(key);
				collect(inner);
				break;
			}

			default: {
				// should be a top level item, UUID key to a map, or a map
				Object s = map.get(key);
				if (s instanceof String) {
					StringBuilder builder = new StringBuilder();
					builder.append("__");
					builder.append(":");
					builder.append(key);
					cache.put(builder.toString(), String.valueOf(s));
				} else {

					Iterator<String> iterInner = ((Map<String, Object>) s)
							.keySet().iterator();
					String uuidTail = null;
					while (iterInner.hasNext()) {
						String tokenKey = iterInner.next();
						String tokenValue = String
								.valueOf(((Map<String, Object>) s)
										.get(tokenKey));
						StringBuilder builder = new StringBuilder();
						String _uuid = normalizeUUID(key);
						uuidTail = _uuid;
						builder.append(_uuid);
						builder.append(":");
						builder.append(tokenKey);
						cache.put(builder.toString(), tokenValue);
					}
					// kind of a virtual attribute
					if (uuidTail != null) {
						cache.put(uuidTail + ":Handle", uuidTail);
					}
				}
			}
			}
		}
	}

	private String normalizeUUID(String in) {
		if (in.endsWith("-P") || in.endsWith("-U") || in.endsWith("-S")) {
			return in.substring(0, in.length() - 2);
		} else
			return in;
	}

	public Map<String, Object> getObjectGraph() {
		return objectGraph;
	}

	public Map<String, String> getCache() {
		return cache;
	}

	public boolean isDebugMode() {
		return debugMode;
	}

	public void setDebugMode(boolean debugMode) {
		this.debugMode = debugMode;
	}

}
