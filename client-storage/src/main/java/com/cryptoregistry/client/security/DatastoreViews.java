package com.cryptoregistry.client.security;
import java.util.Map;

import com.cryptoregistry.CryptoContact;
import com.cryptoregistry.CryptoKey;
import com.cryptoregistry.ListData;
import com.cryptoregistry.MapData;
import com.cryptoregistry.client.storage.Criteria;
import com.cryptoregistry.client.storage.Handle;
import com.cryptoregistry.client.storage.Metadata;
import com.cryptoregistry.client.storage.Result;
import com.cryptoregistry.client.storage.SecureData;
import com.cryptoregistry.signature.CryptoSignature;

public interface DatastoreViews {

	public  Map<Handle, SecureData> getSecureMap();

	public  Map<Handle, Metadata> getMetadataMap();

	public  void put(String regHandle, CryptoKey key);

	public  void put(String regHandle, CryptoContact contact);

	public  void put(String regHandle, CryptoSignature signature);

	public  void put(String regHandle, MapData local);

	public  void put(String regHandle, ListData remote);
	
	public void get(Criteria criteria) throws SuitableMatchFailedException;
	
	/**
	 * Actual handle, not reg handle here
	 * 
	 * @param handle
	 * @param result
	 * @throws SuitableMatchFailedException
	 */
	public void get(String handle, Result result) throws SuitableMatchFailedException;
	
	


}