/*
 *  This file is part of Buttermilk
 *  Copyright 2011-2014 David R. Smith All Rights Reserved.
 *
 */
package com.cryptoregistry.symmetric;

import x.org.bouncycastle.crypto.engines.AESFastEngine;
import x.org.bouncycastle.crypto.modes.CBCBlockCipher;
import x.org.bouncycastle.crypto.paddings.PKCS7Padding;
import x.org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import x.org.bouncycastle.crypto.params.KeyParameter;
import x.org.bouncycastle.crypto.params.ParametersWithIV;

/**
 * Standard block cipher encryption using AES CBC and PKCS7 for padding. 
 * 
 * @author Dave
 *
 */
public class AESCBCPKCS7 {

	private final byte [] key;
	private final byte [] iv;
	private boolean ENCRYPT_MODE;
	
	ParametersWithIV holder;
	CBCBlockCipher blockCipher;
	PaddedBufferedBlockCipher aesCipher;
	
	public AESCBCPKCS7(byte [] key, byte [] iv) {
		this.key = key;
		this.iv = iv;
		init(true);
	}
	
	// internally prep the cipher as required, which allows it to be reused for multiple calls
	public void init(boolean mode){
		holder = this.buildKey();
		blockCipher = new CBCBlockCipher(new AESFastEngine());
		aesCipher = new PaddedBufferedBlockCipher(blockCipher, new PKCS7Padding());
		aesCipher.init(mode, holder);
		ENCRYPT_MODE = mode;
	}
	
	public byte [] encrypt(byte [] input) {
		if(!ENCRYPT_MODE){
			init(true);
		}
		return genCipherData(aesCipher, input);
	}
	
	public byte [] decrypt(byte [] encrypted) {
		if(ENCRYPT_MODE){
			init(false);
		}
		return genCipherData(aesCipher, encrypted);
	}
	
	private byte[] genCipherData(PaddedBufferedBlockCipher cipher, byte[] data) {
	    int minSize = cipher.getOutputSize(data.length);
	    byte[] outBuf = new byte[minSize];
	    int length1 = cipher.processBytes(data, 0, data.length, outBuf, 0);
	    int length2 = cipher.doFinal(outBuf, length1);
	    int actualLength = length1 + length2;
	    byte[] result = new byte[actualLength];
	    System.arraycopy(outBuf, 0, result, 0, result.length);
	    return result;
	}
	
	private ParametersWithIV buildKey() {
		ParametersWithIV holder = new ParametersWithIV(
				new KeyParameter(key, 0, key.length), 
				iv, 
				0, 
				iv.length);
		return holder;
	}

}
