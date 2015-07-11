/*
 *  This file is part of Buttermilk
 *  Copyright 2011-2014 David R. Smith All Rights Reserved.
 *
 */
package com.cryptoregistry.c2;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.concurrent.locks.ReentrantLock;

import net.iharder.Base64;
import x.org.bouncycastle.crypto.Digest;
import x.org.bouncycastle.crypto.digests.SHA256Digest;

import com.cryptoregistry.CryptoKey;
import com.cryptoregistry.KeyGenerationAlgorithm;
import com.cryptoregistry.c2.key.AgreementPrivateKey;
import com.cryptoregistry.c2.key.C2KeyMetadata;
import com.cryptoregistry.c2.key.Curve25519KeyContents;
import com.cryptoregistry.c2.key.Curve25519KeyForPublication;
import com.cryptoregistry.c2.key.PublicKey;
import com.cryptoregistry.c2.key.SecretKey;
import com.cryptoregistry.c2.key.SigningPrivateKey;
import com.cryptoregistry.signature.C2CryptoSignature;
import com.cryptoregistry.signature.C2Signature;
import com.cryptoregistry.signature.SignatureMetadata;
import com.cryptoregistry.util.XORUtil;

/**
 * <pre>
 * CryptoFactory provides some of the classes one would expect when doing cryptography, such as
 * PrivateKey, PublicKey, and so on. These classes do not implement the javax.crypto interfaces.
 * Example use for ECDH:
 * 
   Curve25519KeyContents keys0 = CryptoFactory.INSTANCE.generateKeys();
   Curve25519KeyContents keys1 = CryptoFactory.INSTANCE.generateKeys();
   SecretKey s0 = CryptoFactory.INSTANCE.keyAgreement(keys1.publicKey, keys0.agreementPrivateKey);
   SecretKey s1 = CryptoFactory.INSTANCE.keyAgreement(keys0.publicKey, keys1.agreementPrivateKey);
   Assert.assertTrue(test_equal(s0.getBytes(),s1.getBytes()));
   s0.selfDestruct();
   s1.selfDestruct(); // remove the key bytes from the heap memory after use
		
 * 
 * </pre>
 * 
 * @author Dave
 *
 */
public class CryptoFactory {

	private final Curve25519 curve;
	private final ReentrantLock lock;
	private final SecureRandom rand;
	
	public static final CryptoFactory INSTANCE = new CryptoFactory();
	
	private CryptoFactory() {
		curve = new Curve25519();
		lock = new ReentrantLock();
		try {
			rand = SecureRandom.getInstance("SHA1PRNG");
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException(e);
		}
	}
	
	/**
	 * Apply a runtime cast to a key known only by its metadata
	 * 
	 * @param key
	 * @return
	 */
	public Curve25519KeyForPublication narrow(CryptoKey key) {
		if(key.getMetadata().getKeyAlgorithm() == KeyGenerationAlgorithm.Curve25519) {
				return (Curve25519KeyForPublication) key;
		}
		else return null;
	}
	
	public Curve25519KeyContents generateKeys(){
		lock.lock();
		try {
			byte[]P=new byte[32];
			byte[]s=new byte[32];
			byte[]k=new byte[32];
			rand.nextBytes(k);
			curve.keygen(P, s, k);
			return new Curve25519KeyContents(new PublicKey(P),new SigningPrivateKey(s),new AgreementPrivateKey(k));
		}finally{
			lock.unlock();
		}
	}
	
	public Curve25519KeyContents generateKeys(C2KeyMetadata management){
		lock.lock();
		try {
			byte[]P=new byte[32];
			byte[]s=new byte[32];
			byte[]k=new byte[32];
			rand.nextBytes(k);
			curve.keygen(P, s, k);
			return new Curve25519KeyContents(management, new PublicKey(P),new SigningPrivateKey(s),new AgreementPrivateKey(k));
		}finally{
			lock.unlock();
		}
	}
	
	public SecretKey keyAgreement(PublicKey peerPublicKey, AgreementPrivateKey privKey){
		lock.lock();
		try {
			byte [] Z = new byte[32];
			curve.curve(Z, privKey.getBytes(), peerPublicKey.getBytes());
			return new SecretKey(Z);
		}finally{
			lock.unlock();
		}
	}
	
	/* Signature verification primitive, calculates Y = vP + hG
	 *   Y  [out] signature public key
	 *   v  [in]  signature value
	 *   h  [in]  signature hash
	 *   P  [in]  public key
	 */
	
	public boolean verify(Curve25519KeyForPublication cpKey, byte[]msgBytes, C2Signature sig, Digest digest){
		lock.lock();
		try {
			Curve25519 c2 = curve;
			PublicKey pKey = cpKey.publicKey;
			byte [] v = sig.v.decodeToBytes();
			byte [] r = sig.r.decodeToBytes();
			
			// compute m 
			//SHA256Digest digest = new SHA256Digest();
			digest.update(pKey.getBytes(), 0, pKey.length());
			digest.update(msgBytes, 0, msgBytes.length);
			byte [] m = new byte[digest.getDigestSize()];
			digest.doFinal(m, 0);
			
			try {
				System.err.println("verifying c2 message digest="+Base64.encodeBytes(m, Base64.URL_SAFE));
			} catch (IOException e) {
				e.printStackTrace();
			}
			
			// compute h: m XOR r
			byte [] h = XORUtil.xor(m, r);
			
			byte [] Yx = new byte[32];
			c2.verify(Yx, v, h, pKey.getBytes());
			
			// hash of Yx, should equal r
			digest.update(Yx, 0, Yx.length);
			byte [] hx = new byte[digest.getDigestSize()];
			digest.doFinal(hx, 0);
			
			return test_equal(hx,r);
		
		}finally{
			lock.unlock();
		}
	}
	
	private boolean test_equal(byte[] a, byte[] b) {
		int i;
		for (i = 0; i < 32; i++) {
			if (a[i] != b[i]) {
				return false;
			}
		}
		return true;
	}
	
	/* Signature generation primitive, calculates (x-h)s mod q
	 *   v  [out] signature value
	 *   h  [in]  signature hash (of message, signature pub key, and context data)
	 *   x  [in]  signature private key
	 *   s  [in]  private key for signing
	 * returns true on success, false on failure (use different x or h)
	 * 
	 * we will throw a runtime exception if false
	 */
	
	public C2CryptoSignature sign(SignatureMetadata meta, Curve25519KeyContents c2Keys, byte[]msgBytes, Digest digest){
		
		lock.lock();
		try {
			Curve25519 c2 = curve;
			SigningPrivateKey spk = c2Keys.signingPrivateKey;
			PublicKey pKey = c2Keys.publicKey;
			
			// compute m
			//SHA256Digest digest = new SHA256Digest();
			digest.update(pKey.getBytes(), 0, pKey.length());
			digest.update(msgBytes, 0, msgBytes.length);
			byte [] m = new byte[digest.getDigestSize()];
			digest.doFinal(m, 0);
			
			try {
				System.err.println("signing c2 message digest="+Base64.encodeBytes(m, Base64.URL_SAFE));
			} catch (IOException e) {
				e.printStackTrace();
			}
			
			// compute x
		//	digest = new SHA256Digest();
			digest.reset();
			digest.update(m, 0, m.length);
			digest.update(spk.getBytes(), 0, spk.length());
			byte [] x = new byte[digest.getDigestSize()];
			digest.doFinal(x, 0);
			
			// compute Y
			// 	 keygen25519(Y, NULL, x);
			byte [] Y = new byte[digest.getDigestSize()];
			c2.keygen(Y, null, x);
			
			// compute r
			byte [] r = new byte[digest.getDigestSize()];
			digest.update(Y,0,Y.length);
			digest.doFinal(r, 0);
			
			// compute h: m XOR r
			byte [] h = XORUtil.xor(m, r);
			
			// sign, v is the signature
			byte [] v = new byte[digest.getDigestSize()];
			boolean ok = c2.sign(v, h, x, spk.getBytes());
			if(!ok) throw new RuntimeException("signature process failed");
			
			if(v.length != r.length){
				throw new RuntimeException("v,r should be of equal length");
			}
			C2Signature sig = new C2Signature(v,r);
			return new C2CryptoSignature(meta, sig);
			
		}finally{
			lock.unlock();
		}
	}
	
	public C2CryptoSignature sign(String signedBy, Curve25519KeyContents c2Keys, byte[]msgBytes, Digest digest){
		lock.lock();
		try {
			Curve25519 c2 = curve;
			SigningPrivateKey spk = c2Keys.signingPrivateKey;
			PublicKey pKey = c2Keys.publicKey;
			
			// compute m
			//SHA256Digest digest = new SHA256Digest();
			digest.update(pKey.getBytes(), 0, pKey.length());
			digest.update(msgBytes, 0, msgBytes.length);
			byte [] m = new byte[digest.getDigestSize()];
			digest.doFinal(m, 0);
			
			try {
				System.err.println("signing c2 message digest="+Base64.encodeBytes(m, Base64.URL_SAFE));
			} catch (IOException e) {
				e.printStackTrace();
			}
			
			// compute x
			//digest = new SHA256Digest();
			digest.reset();
			digest.update(m, 0, m.length);
			digest.update(spk.getBytes(), 0, spk.length());
			byte [] x = new byte[digest.getDigestSize()];
			digest.doFinal(x, 0);
			
			// compute Y
			// 	 keygen25519(Y, NULL, x);
			byte [] Y = new byte[32];
			c2.keygen(Y, null, x);
			
			// compute r
			byte [] r = new byte[digest.getDigestSize()];
			digest.update(Y,0,Y.length);
			digest.doFinal(r, 0);
			
			// compute h: m XOR r
			byte [] h = XORUtil.xor(m, r);
			
			// sign, v is the signature
			byte [] v = new byte[32];
			boolean ok = c2.sign(v, h, x, spk.getBytes());
			if(!ok) throw new RuntimeException("signature process failed");
			
			C2Signature sig = new C2Signature(v,r);
			return new C2CryptoSignature(c2Keys.metadata.getHandle(),signedBy,sig);
			
		}finally{
			lock.unlock();
		}
	}
	
}
