package com.cryptoregistry.symmetric;

import x.org.bouncycastle.crypto.engines.AESFastEngine;
import x.org.bouncycastle.crypto.modes.GCMBlockCipher;
import x.org.bouncycastle.crypto.params.KeyParameter;
import x.org.bouncycastle.crypto.params.ParametersWithIV;

public class AESGCM {

	private final byte [] key;
	private final byte [] iv;
	
	public AESGCM(byte [] key, byte [] iv) {
		this.key = key;
		this.iv = iv;
	}
	
	public byte [] encrypt(byte [] input) {
		ParametersWithIV holder = this.buildKey();
		GCMBlockCipher aesCipher = new GCMBlockCipher(new AESFastEngine());
		aesCipher.init(true, holder);
		byte [] encrypted = genCipherData(aesCipher, input);
		return encrypted;
	}
	
	public byte [] decrypt(byte [] encrypted) {
		ParametersWithIV holder = this.buildKey();
		GCMBlockCipher aesCipher = new GCMBlockCipher(new AESFastEngine());
		aesCipher.init(false, holder);
		return genCipherData(aesCipher, encrypted);
	}
	
	private byte[] genCipherData(GCMBlockCipher cipher, byte[] data) {
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
