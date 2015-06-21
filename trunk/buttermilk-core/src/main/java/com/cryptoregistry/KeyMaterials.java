/*
 *  This file is part of Buttermilk
 *  Copyright 2011-2014 David R. Smith All Rights Reserved.
 *
 */
package com.cryptoregistry;

import java.util.List;
import java.util.Map;

import com.cryptoregistry.signature.CryptoSignature;


/**
 * Holders for output of the JSONReader class must implement this interface
 * 
 * @author Dave
 *
 */
public interface KeyMaterials {
	
	String version();
	String regHandle();
	String email();
	
	// value object support
	List<CryptoKeyWrapper> keys();
	List<CryptoContact> contacts();
	List<CryptoSignature> signatures();
	List<MapData> mapData();
	List<ListData> listData();
	
	//serialized Map support
	
	List<MapData> keyMaps();
	List<MapData> contactMaps();
	List<MapData> signatureMaps();
	List<MapData> mapDataMaps();
	//List<ListData> listDataMaps();
	
	Map<String,Object> baseMap();
	
}
