/*
 *  This file is part of Buttermilk
 *  Copyright 2011-2014 David R. Smith All Rights Reserved.
 *
 */
package com.cryptoregistry;

import java.io.UnsupportedEncodingException;
import java.util.Iterator;
import java.util.Map;

import com.cryptoregistry.formats.C2KeyFormatReader;
import com.cryptoregistry.formats.ECKeyFormatReader;
import com.cryptoregistry.formats.KeyEncryptor;
import com.cryptoregistry.formats.KeyHolder;
import com.cryptoregistry.formats.NTRUKeyFormatReader;
import com.cryptoregistry.formats.RSAKeyFormatReader;
import com.cryptoregistry.formats.SymmetricKeyFormatReader;
import com.cryptoregistry.passwords.Password;
import com.cryptoregistry.pbe.ArmoredPBEResult;
import com.cryptoregistry.pbe.ArmoredPBKDF2Result;
import com.cryptoregistry.pbe.ArmoredScryptResult;
import com.cryptoregistry.pbe.PBE;
import com.cryptoregistry.pbe.PBEAlg;
import com.cryptoregistry.pbe.PBEParams;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * <pre>
 * After key materials are parsed, we may not know at runtime what kind of keys they represent. 
 * This wrapper allows us to gain runtime information about what was parsed. 
 * 
 * General use:
 * 
 * isSecure() - tells us if the object is an instance of ArmoredPBEResult
 * getMetadata() - if not secure, we can get the key generation algorithm with this method
 * getKeyContents() - returns a CryptoKey
 * 
 * </pre>
 * @author Dave
 *
 */
public class CryptoKeyWrapperImpl implements CryptoKeyWrapper {

	private Object wrapped;

	public CryptoKeyWrapperImpl(Object wrapped) {
		super();
		this.wrapped = wrapped;
	}

	@Override
	public CryptoKeyMetadata getMetadata() {
		if(!(wrapped instanceof ArmoredPBEResult)){
			return ((CryptoKey)wrapped).getMetadata();
		}else{
			return null;
		}
	}

	@Override
	public Class<?> getWrappedType() {
		return wrapped.getClass();
	}

	@Override
	public boolean isForPublication() {
		return wrapped instanceof Verifier && !(wrapped instanceof Signer);
	}

	@Override
	public boolean isSecure() {
		return wrapped instanceof ArmoredPBEResult;
	}

	@Override
	public boolean unlock(Password password) {
		
		// TODO update with KeyDecryptor
		
		if(wrapped instanceof ArmoredPBEResult){
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
						wrapped = reader.read();
						break;
					}
					case Curve25519: {
						C2KeyFormatReader reader = new C2KeyFormatReader(map);
						wrapped = reader.read();
						break;
					}
					case EC:{
						ECKeyFormatReader reader = new ECKeyFormatReader(map);
						wrapped = reader.read();
						break;
					}
					case RSA:{
						RSAKeyFormatReader reader = new RSAKeyFormatReader(map);
						wrapped = reader.read();
						break;
					}
					case NTRU: {
						NTRUKeyFormatReader reader = new NTRUKeyFormatReader(map);
						wrapped = reader.read();
						break;
					}
					
					default: throw new RuntimeException("Unknown KeyGenerationAlgorithm: "+keyAlgorithm);
				}
				
				return true;
				
			} catch (Exception e) {
				throw new RuntimeException(e);
			}
			
		}else{
			return false;
		}
	}

	@Override
	public void lock(PBEParams params) {
		if(!(wrapped instanceof Signer)) throw new RuntimeException("Cannot lock key unless it implements Signer");
		KeyHolder holder = new KeyHolder(this.getKeyContents());
		KeyEncryptor enc = new KeyEncryptor(holder);
		wrapped = enc.wrap(params);
	}

	@Override
	public CryptoKey getKeyContents() {
		return (CryptoKey) wrapped;
	}

	@Override
	public void setKeyContents(Object obj) {
		this.wrapped = obj;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((wrapped == null) ? 0 : wrapped.hashCode());
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
		CryptoKeyWrapperImpl other = (CryptoKeyWrapperImpl) obj;
		if (wrapped == null) {
			if (other.wrapped != null)
				return false;
		} else if (!wrapped.equals(other.wrapped))
			return false;
		return true;
	}

	@Override
	public String toString() {
		return "CryptoKeyWrapperImpl [wrapped=" + wrapped + "]";
	}
}
