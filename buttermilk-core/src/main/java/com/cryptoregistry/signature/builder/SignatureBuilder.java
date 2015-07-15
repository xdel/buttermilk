package com.cryptoregistry.signature.builder;

import java.io.IOException;

import com.cryptoregistry.signature.SignatureMetadata;

import net.iharder.Base64;

/**
 * Base class, provides the debug/tracing common code
 * 
 * @author Dave
 *
 */
public class SignatureBuilder {
	
	protected boolean debugMode;
	int startIndex=0, endIndex=0;

	public SignatureBuilder() {}
	
	public SignatureBuilder(boolean debug) {
		this.debugMode=debug;
	}

	public boolean isDebugMode() {
		return debugMode;
	}

	public void setDebugMode(boolean debugMode) {
		this.debugMode = debugMode;
	}
	
	protected void log(String label, byte [] bytes){
		if(debugMode){
			startIndex = endIndex;
			endIndex+=bytes.length;
			try {
				System.err.println("update="+label+", "+Base64.encodeBytes(bytes, Base64.URL_SAFE)+" start:"+startIndex+", end:"+endIndex);
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
	}
	
	protected void log(SignatureMetadata meta, byte [] bytes){
		if(debugMode){
			try {
				System.err.println(meta.sigAlg.toString()+" "+meta.handle+" message digest="+Base64.encodeBytes(bytes, Base64.URL_SAFE));
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
	}
	
	protected void log(SignatureMetadata meta, int count){
		System.err.println(meta.sigAlg.toString()+" "+meta.handle+" digest consumed "+count+" bytes");
	}

}
