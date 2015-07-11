/*
 *  This file is part of Buttermilk
 *  Copyright 2011-2014 David R. Smith All Rights Reserved.
 *
 */
package com.cryptoregistry.ec;

import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.concurrent.locks.ReentrantLock;

import com.cryptoregistry.SignatureAlgorithm;
import com.cryptoregistry.signature.ECDSACryptoSignature;
import com.cryptoregistry.signature.ECDSASignature;


import com.cryptoregistry.signature.SignatureMetadata;

import x.org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import x.org.bouncycastle.crypto.Digest;
import x.org.bouncycastle.crypto.agreement.ECDHBasicAgreement;
import x.org.bouncycastle.crypto.digests.SHA1Digest;
import x.org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import x.org.bouncycastle.crypto.params.ECDomainParameters;
import x.org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import x.org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import x.org.bouncycastle.crypto.params.ECPublicKeyParameters;
import x.org.bouncycastle.crypto.params.ParametersWithRandom;
import x.org.bouncycastle.crypto.signers.ECDSASigner;
import x.org.bouncycastle.crypto.signers.HMacDSAKCalculator;

public class CryptoFactory {

	private final ReentrantLock lock;
	private final SecureRandom rand;

	public static final CryptoFactory INSTANCE = new CryptoFactory();
	
	public static final int SHA1_SIZE = new SHA1Digest().getDigestSize();

	private CryptoFactory() {
		lock = new ReentrantLock();
		try {
			rand = SecureRandom.getInstance("SHA1PRNG");
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException(e);
		}
	}

	public ECKeyContents generateKeys(final String curveName) {
		lock.lock();
		try {
			ECKeyPairGenerator gen = new ECKeyPairGenerator();
			ECDomainParameters domainParams = CurveFactory.getCurveForName(curveName);
			ECKeyGenerationParameters params = new ECKeyGenerationParameters(domainParams,rand);
			gen.init(params);
			AsymmetricCipherKeyPair pair = gen.generateKeyPair();
			ECPrivateKeyParameters priv = (ECPrivateKeyParameters) pair.getPrivate();
			ECPublicKeyParameters pub = (ECPublicKeyParameters) pair.getPublic();
			return new ECKeyContents(pub.getQ(),priv.getParameters().getName(),priv.getD());
		} finally {
			lock.unlock();
		}
	}
	
	/**
	 * Custom Curve interface
	 * 
	 * @param domainParams
	 * @return
	 */
	public ECKeyContents generateCustomKeys(ECCustomParameters domainParams) {
		lock.lock();
		try {
			ECKeyPairGenerator gen = new ECKeyPairGenerator();
			ECKeyGenerationParameters params = new ECKeyGenerationParameters(domainParams.getParameters(),rand);
			gen.init(params);
			AsymmetricCipherKeyPair pair = gen.generateKeyPair();
			ECPrivateKeyParameters priv = (ECPrivateKeyParameters) pair.getPrivate();
			ECPublicKeyParameters pub = (ECPublicKeyParameters) pair.getPublic();
			return new ECKeyContents(pub.getQ(),domainParams,priv.getD());
		} finally {
			lock.unlock();
		}
	}
	
	/**
	 * Use for Mode.SEALED key setup
	 * @param password
	 * @param curveName
	 * @return
	 */
	public ECKeyContents generateKeys(char [] password, final String curveName) {
		lock.lock();
		try {
			ECKeyPairGenerator gen = new ECKeyPairGenerator();
			ECDomainParameters domainParams = CurveFactory.getCurveForName(curveName);
			ECKeyGenerationParameters params = new ECKeyGenerationParameters(domainParams,rand);
			gen.init(params);
			AsymmetricCipherKeyPair pair = gen.generateKeyPair();
			ECPrivateKeyParameters priv = (ECPrivateKeyParameters) pair.getPrivate();
			ECPublicKeyParameters pub = (ECPublicKeyParameters) pair.getPublic();
			return new ECKeyContents(password,pub.getQ(),priv.getParameters().getName(),priv.getD());
		} finally {
			lock.unlock();
		}
	}
	
	public ECKeyContents generateKeys(ECKeyMetadata meta, final String curveName) {
		lock.lock();
		try {
			ECKeyPairGenerator gen = new ECKeyPairGenerator();
			ECDomainParameters domainParams = CurveFactory.getCurveForName(curveName);
			ECKeyGenerationParameters params = new ECKeyGenerationParameters(domainParams,rand);
			gen.init(params);
			AsymmetricCipherKeyPair pair = gen.generateKeyPair();
			ECPrivateKeyParameters priv = (ECPrivateKeyParameters) pair.getPrivate();
			ECPublicKeyParameters pub = (ECPublicKeyParameters) pair.getPublic();
			return new ECKeyContents(meta,pub.getQ(),priv.getParameters().getName(),priv.getD());
		} finally {
			lock.unlock();
		}
	}
	
	/**
	 * Does EC Diffie-Hellman key agreement. Returns a SHA-256 digest of the result suitable for use
	 * as an encryption key
	 * 
	 * @param ours
	 * @param theirs
	 * @return
	 */
	public byte [] keyAgreement(ECKeyContents ours, ECKeyForPublication theirs){
		lock.lock();
		try {
			ECDHBasicAgreement agree = new ECDHBasicAgreement();
			agree.init(ours.getPrivateKey());
			BigInteger bi = agree.calculateAgreement(theirs.getPublicKey());
			Digest digest = new SHA1Digest();
			byte [] bytes = bi.toByteArray();
			digest.update(bytes, 0, bytes.length);
			byte[]  digestBytes = new byte[digest.getDigestSize()];
		    digest.doFinal(digestBytes, 0);
		    return digestBytes;
		} finally {
			lock.unlock();
		}
	}
	
	/**
	 * The option to use a different digest
	 * 
	 * @param ours
	 * @param theirs
	 * @param digest
	 * @return
	 */
	public byte [] keyAgreement(ECKeyContents ours, ECKeyForPublication theirs, Digest digest){
		lock.lock();
		try {
			ECDHBasicAgreement agree = new ECDHBasicAgreement();
			agree.init(ours.getPrivateKey());
			BigInteger bi = agree.calculateAgreement(theirs.getPublicKey());
			byte [] bytes = bi.toByteArray();
			digest.update(bytes, 0, bytes.length);
			byte[]  digestBytes = new byte[digest.getDigestSize()];
		    digest.doFinal(digestBytes, 0);
		    return digestBytes;
		} finally {
			lock.unlock();
		}
	}
	
	/**
	 * Deterministic ECDSA with SHA1. 
	 * 
	 * @param signedBy
	 * @param ecKeys
	 * @param msgHashBytes
	 */
	public ECDSACryptoSignature sign(String signedBy, ECKeyContents ecKeys, byte[] msgHashBytes){
		lock.lock();
		
		if(msgHashBytes.length!=SHA1_SIZE) throw new RuntimeException("This method requires a SHA1 digest input");
		try {
			Digest digest = new SHA1Digest();
			ECDSASigner signer = new ECDSASigner(new HMacDSAKCalculator(digest));
			ParametersWithRandom param = new ParametersWithRandom(ecKeys.getPrivateKey(), rand);
			signer.init(true, param);
			BigInteger [] sigRes = signer.generateSignature(msgHashBytes);
			ECDSASignature esig =  new ECDSASignature(sigRes[0],sigRes[1]);
			SignatureMetadata meta = new SignatureMetadata(
					SignatureAlgorithm.ECDSA,
					digest.getAlgorithmName(),
					ecKeys.getMetadata().getHandle(),
					signedBy);
			return new ECDSACryptoSignature(meta, esig);
		} finally {
			lock.unlock();
		}
	}
	
	/**
	 *  Deterministic ECDSA with SHA1. If SignatureMetadata contains some other sized digest algorithm,
	 *  then SHA1ify the bytes.
	 *  
	 * @param meta
	 * @param ecKeys
	 * @param msgHashBytes
	 * @return
	 */
	public ECDSACryptoSignature sign(SignatureMetadata meta, ECKeyContents ecKeys, byte[] msgHashBytes){
		lock.lock();
		try {
			byte [] hash = null;
			if(msgHashBytes.length != SHA1_SIZE){
				SHA1Digest digest = new SHA1Digest();
				digest.update(msgHashBytes, 0, msgHashBytes.length);
				hash = new byte[digest.getDigestSize()];
				digest.doFinal(hash, 0);
			}else{
				hash = msgHashBytes;
			}
			
			ECDSASigner signer = new ECDSASigner(new HMacDSAKCalculator(new SHA1Digest()));
			ParametersWithRandom param = new ParametersWithRandom(ecKeys.getPrivateKey(), rand);
			signer.init(true, param);
			BigInteger [] sigRes = signer.generateSignature(hash);
			ECDSASignature esig =  new ECDSASignature(sigRes[0],sigRes[1]);
			return new ECDSACryptoSignature(meta,esig);
		} finally {
			lock.unlock();
		}
	}
	
	/**
	 *  Deterministic ECDSA. If the digest is larger than SHA1, then re-
	 * @param sig
	 * @param pKey
	 * @param msgHashBytes
	 * @return
	 */
	public boolean verify(ECDSACryptoSignature sig,ECKeyForPublication pKey, byte [] msgHashBytes){
		lock.lock();
		try {
			byte [] hash = null;
			if(msgHashBytes.length != SHA1_SIZE){
				SHA1Digest digest = new SHA1Digest();
				digest.update(msgHashBytes, 0, msgHashBytes.length);
				hash = new byte[digest.getDigestSize()];
				digest.doFinal(hash, 0);
			}else{
				hash = msgHashBytes;
			}
			ECDSASigner signer = new ECDSASigner(new HMacDSAKCalculator(new SHA1Digest()));
			signer.init(false, pKey.getPublicKey());
			return signer.verifySignature(hash, sig.signature.r, sig.signature.s);
		} finally {
			lock.unlock();
		}
	}
	
	
	
}
