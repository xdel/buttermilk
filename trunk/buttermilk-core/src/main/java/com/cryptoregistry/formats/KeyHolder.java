package com.cryptoregistry.formats;

import com.cryptoregistry.CryptoKey;
import com.cryptoregistry.c2.key.Curve25519KeyContents;
import com.cryptoregistry.ec.ECKeyContents;
import com.cryptoregistry.ntru.NTRUKeyContents;
import com.cryptoregistry.rsa.RSAKeyContents;
import com.cryptoregistry.symmetric.SymmetricKeyContents;

public class KeyHolder {

	final Curve25519KeyContents c2Keys;
	final ECKeyContents ecKeys;
	final RSAKeyContents rsaKeys;
	final NTRUKeyContents ntruKeys;
	final SymmetricKeyContents sKeys;
	
	public KeyHolder(CryptoKey key) {
		switch(key.getMetadata().getKeyAlgorithm()) {
			case Symmetric: {
				sKeys = (SymmetricKeyContents)key; 
				c2Keys = null;
				ecKeys = null;
				rsaKeys = null;
				ntruKeys = null;
				break;
			}
			case Curve25519: {
				c2Keys = (Curve25519KeyContents)key; 
				sKeys = null;
				ecKeys = null;
				rsaKeys = null;
				ntruKeys = null;
				break;
			}
			case EC: {
				sKeys = null;
				c2Keys = null;
				ecKeys = (ECKeyContents) key; 
				rsaKeys = null;
				ntruKeys = null;
				break;
			}
			case RSA: {
				sKeys = null;
				c2Keys = null;
				ecKeys = null;
				rsaKeys = (RSAKeyContents)key; 
				ntruKeys = null;
				break;
			}
			case DSA: {
				ntruKeys =null;
				sKeys = null;
				c2Keys = null;
				ecKeys = null;
				rsaKeys = null;
				break;
			}
			case NTRU: {
				ntruKeys = (NTRUKeyContents)key; 
				sKeys = null;
				c2Keys = null;
				ecKeys = null;
				rsaKeys = null;
				break;
			}
			default: {
				ntruKeys =null;
				sKeys = null;
				c2Keys = null;
				ecKeys = null;
				rsaKeys = null;
				break;
			}
		}
	}

}
