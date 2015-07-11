package com.cryptoregistry.formats;

import java.io.File;
import java.util.List;

import junit.framework.Assert;

import org.junit.Test;

import com.cryptoregistry.CryptoContact;
import com.cryptoregistry.CryptoKeyWrapper;
import com.cryptoregistry.KeyMaterials;
import com.cryptoregistry.MapData;
import com.cryptoregistry.ListData;
import com.cryptoregistry.signature.CryptoSignature;

public class GeneralReadingTest {

	@Test
	public void test0() {
		File f = new File("src/test/resources/keys.test.json");
		JSONReader reader = new JSONReader(f);
		KeyMaterials km = reader.parse();
		List<CryptoKeyWrapper> list = km.keys();
		for(CryptoKeyWrapper wrapper: list){
			System.err.println(wrapper);
		}
		Assert.assertTrue(list.size() == 3);
	}
	
	@Test
	public void test0Generic() {
		File f = new File("src/test/resources/keys.test.json");
		JSONGenericReader reader = new JSONGenericReader(f);
		List<MapData> list = reader.keys();
		Assert.assertEquals(3, list.size());
		MapData md = list.get(0);
		String json = md.formatJSON();
		//System.err.println(json);
		Assert.assertNotNull(json);
	}
	
	@Test
	public void test1() {
		
		File f = new File("src/test/resources/com/cryptoregistry/signature/full0.json");
		JSONReader reader = new JSONReader(f);
		KeyMaterials km = reader.parse();
		
		Assert.assertTrue(km.keys() != null);
		Assert.assertTrue(km.contacts() != null);
		Assert.assertTrue(km.signatures() != null);
		Assert.assertTrue(km.mapData() != null);
		Assert.assertTrue(km.listData() != null);
		
		for(CryptoKeyWrapper wrapper: km.keys()){
			System.err.println(wrapper);
		}
		
		for(CryptoContact wrapper: km.contacts()){
			System.err.println(wrapper);
		}
		
		for(CryptoSignature wrapper: km.signatures()){
			System.err.println(wrapper);
		}
		
		for(MapData wrapper: km.mapData()){
			System.err.println(wrapper);
		}
		
		for(ListData wrapper: km.listData()){
			System.err.println(wrapper);
		}
		
	}
	
	
	
	@Test
	public void test3() {
		
		File f = new File("src/test/resources/com/cryptoregistry/signature/c2.json");
		JSONReader reader = new JSONReader(f);
		KeyMaterials km = reader.parse();
		
		Assert.assertTrue(km.keys() != null);
		Assert.assertTrue(km.contacts() != null);
		Assert.assertTrue(km.signatures() != null);
		Assert.assertTrue(km.mapData() != null);
		Assert.assertTrue(km.listData() != null);
		
		for(CryptoKeyWrapper wrapper: km.keys()){
			System.err.println(wrapper);
		}
		
		for(CryptoContact wrapper: km.contacts()){
			System.err.println(wrapper);
		}
		
		for(CryptoSignature wrapper: km.signatures()){
			System.err.println(wrapper);
		}
		
		for(MapData wrapper: km.mapData()){
			System.err.println(wrapper);
		}
		
		for(ListData wrapper: km.listData()){
			System.err.println(wrapper);
		}
		
	}

}
