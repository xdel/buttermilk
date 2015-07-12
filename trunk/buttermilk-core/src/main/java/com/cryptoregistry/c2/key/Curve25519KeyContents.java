/*
 *  This file is part of Buttermilk
 *  Copyright 2011-2014 David R. Smith All Rights Reserved.
 *
 */
package com.cryptoregistry.c2.key;

import java.util.Arrays;

import com.cryptoregistry.CryptoKey;
import com.cryptoregistry.Signer;
import com.cryptoregistry.passwords.Password;
import com.cryptoregistry.pbe.PBEAlg;
import com.cryptoregistry.pbe.PBEParams;


/**
 * Wrapper for output from the Curve25519 key generation method
 * 
 * @author Dave
 *
 */
public class Curve25519KeyContents extends Curve25519KeyForPublication implements Signer {

	public final SigningPrivateKey signingPrivateKey;
	public final AgreementPrivateKey agreementPrivateKey;
	
	/**
	 * Sets up for public formatting only
	 * @param key0
	 * @param key1
	 * @param key2
	 */
	public Curve25519KeyContents(PublicKey key0, SigningPrivateKey key1, AgreementPrivateKey key2) {
		super(C2KeyMetadata.createUnsecured(), key0);
		signingPrivateKey = key1;
		agreementPrivateKey = key2;
	}
	
	/**
	 * Set up for user choice format options
	 * @param management
	 * @param key0
	 * @param key1
	 * @param key2
	 */
	public Curve25519KeyContents(C2KeyMetadata management, PublicKey key0, SigningPrivateKey key1, AgreementPrivateKey key2) {
		super(management, key0);
		signingPrivateKey = key1;
		agreementPrivateKey = key2;
	}

	public Curve25519KeyContents clone() {
			C2KeyMetadata meta =  super.metadata.clone();
			PublicKey pubKey = (PublicKey) super.publicKey.clone();
			AgreementPrivateKey agree = (AgreementPrivateKey) this.agreementPrivateKey.clone();
			SigningPrivateKey signingKey = (SigningPrivateKey) this.signingPrivateKey.clone();
			Curve25519KeyContents c = new Curve25519KeyContents(meta, pubKey, signingKey, agree);
			return c;
	}
	
	public Curve25519KeyForPublication copyForPublication() {
		C2KeyMetadata meta =  metadata.cloneForPublication();
		PublicKey pubKey = (PublicKey) publicKey.clone();
		Curve25519KeyForPublication  c = new Curve25519KeyForPublication (meta, pubKey);
		return c;
	}
	
	public CryptoKey keyForPublication() {
		return copyForPublication();
	}
	
	
	public Curve25519KeyContents prepareSecure(PBEAlg alg, char [] passwordChars, int ...args) {
		
		PublicKey pubKey = (PublicKey) super.publicKey.clone();
		AgreementPrivateKey agree = (AgreementPrivateKey) this.agreementPrivateKey.clone();
		SigningPrivateKey signingKey = (SigningPrivateKey) this.signingPrivateKey.clone();
		C2KeyMetadata meta = null;
		if(alg == PBEAlg.PBKDF2){
			if(args == null) {
				meta = this.metadata.cloneSecurePBKDF2(passwordChars);
			}else if(args.length == 1){
				meta = this.metadata.cloneSecurePBKDF2(args[0], passwordChars);
			}else{
				throw new RuntimeException("Not sure what to do with the additional args, expected one: "+Arrays.toString(args));
			}
		}else if(alg == PBEAlg.SCRYPT){
			if(args == null) {
				meta = this.metadata.cloneSecureScrypt(passwordChars);
			}else if(args.length == 2){
				meta = this.metadata.cloneSecureScrypt(args[0], args[1], passwordChars);
			}else{
				throw new RuntimeException("Looking for two integers here or none: "+Arrays.toString(args));
			}
		}
		
		return new Curve25519KeyContents(meta, pubKey, signingKey, agree);
	}
	
	/**
	 * If a password is set in the KeyFormat, clean that out. This call can be made once we're done
	 * with the key materials in this cycle of use. 
	 */
	@Override
	public void scrubPassword() {
		PBEParams params = this.metadata.format.pbeParams;
		if(params != null) {
			Password password = params.getPassword();
			if(password != null && password.isAlive()) password.selfDestruct();
		}
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = super.hashCode();
		result = prime
				* result
				+ ((agreementPrivateKey == null) ? 0 : agreementPrivateKey
						.hashCode());
		result = prime
				* result
				+ ((signingPrivateKey == null) ? 0 : signingPrivateKey
						.hashCode());
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (!super.equals(obj))
			return false;
		if (getClass() != obj.getClass())
			return false;
		Curve25519KeyContents other = (Curve25519KeyContents) obj;
		if (agreementPrivateKey == null) {
			if (other.agreementPrivateKey != null)
				return false;
		} else if (!agreementPrivateKey.equals(other.agreementPrivateKey))
			return false;
		if (signingPrivateKey == null) {
			if (other.signingPrivateKey != null)
				return false;
		} else if (!signingPrivateKey.equals(other.signingPrivateKey))
			return false;
		return true;
	}

	

}
