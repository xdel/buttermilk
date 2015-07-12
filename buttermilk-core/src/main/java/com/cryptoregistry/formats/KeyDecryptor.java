package com.cryptoregistry.formats;

import java.io.UnsupportedEncodingException;
import java.util.Iterator;
import java.util.Map;

import com.cryptoregistry.CryptoKey;
import com.cryptoregistry.KeyGenerationAlgorithm;
import com.cryptoregistry.passwords.Password;
import com.cryptoregistry.pbe.ArmoredPBEResult;
import com.cryptoregistry.pbe.ArmoredPBKDF2Result;
import com.cryptoregistry.pbe.ArmoredScryptResult;
import com.cryptoregistry.pbe.PBE;
import com.cryptoregistry.pbe.PBEAlg;
import com.cryptoregistry.pbe.PBEParams;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * Decrypt the Armored form of a confidential key. The type can be acquired using the CryptoKey interface.
 * 
 * @author Dave
 *
 */
public class KeyDecryptor {

	final ArmoredPBEResult wrapped;
	final Password password;
	
	public KeyDecryptor(ArmoredPBEResult item, Password pass) {
		this.wrapped = item;
		this.password= pass;
	}
	
	public CryptoKey unwrap(){
		PBEParams params = null;
		byte [] data = null;
		if(wrapped instanceof ArmoredPBKDF2Result){
			ArmoredPBKDF2Result res = (ArmoredPBKDF2Result) wrapped;
			params = new PBEParams(PBEAlg.PBKDF2);
			params.setSalt(res.getSaltWrapper());
			params.setIterations(res.iterations);
			params.setPassword(password);
			PBE pbe0 = new PBE(params);
			data = pbe0.decrypt(res.getResultBytes());
			
		}else{
			ArmoredScryptResult res = (ArmoredScryptResult) wrapped;
			params = new PBEParams(PBEAlg.SCRYPT);
			
			params.setPassword(password);
			params.setSalt(res.getSaltWrapper());
			params.setIv(res.getIVWrapper());
			params.setBlockSize_r(res.blockSize);
			params.setCpuMemoryCost_N(res.cpuMemoryCost);
			params.setParallelization_p(res.parallelization);
			
			PBE pbe0 = new PBE(params);
			data = pbe0.decrypt(res.getResultBytes());
		}
		
		String reconstructed = null;
		
		try {
			reconstructed = new String(data, "UTF-8");
		} catch (UnsupportedEncodingException e1) {
			e1.printStackTrace();
		}
		
		ObjectMapper mapper = new ObjectMapper();
		String keyAlgorithm = null;
		try {
			// top level map
			@SuppressWarnings("unchecked")
			Map<String,Object> map = (Map<String,Object>) mapper.readValue(reconstructed, Map.class);
			// drill down to get key type
			Iterator<String> iter = map.keySet().iterator();
			if(iter.hasNext()){
				String distUUID = iter.next();
				@SuppressWarnings("unchecked")
				Map<String,Object> inner = (Map<String,Object>) map.get(distUUID);
				keyAlgorithm = String.valueOf(inner.get("KeyAlgorithm"));
			}
			
			KeyGenerationAlgorithm alg = KeyGenerationAlgorithm.valueOf(keyAlgorithm);
			switch(alg){
				case Symmetric: {
					SymmetricKeyFormatReader reader = new SymmetricKeyFormatReader(map);
					return reader.read();
				}
				case Curve25519: {
					C2KeyFormatReader reader = new C2KeyFormatReader(map);
					return reader.read();
				}
				case EC:{
					ECKeyFormatReader reader = new ECKeyFormatReader(map);
					return reader.read();
				}
				case RSA:{
					RSAKeyFormatReader reader = new RSAKeyFormatReader(map);
					return reader.read();
				}
				case NTRU: {
					NTRUKeyFormatReader reader = new NTRUKeyFormatReader(map);
					return reader.read();
				}
				
				default: throw new RuntimeException("Unknown KeyGenerationAlgorithm: "+keyAlgorithm);
			}
			
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}

}
