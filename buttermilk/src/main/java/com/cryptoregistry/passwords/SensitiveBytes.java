package com.cryptoregistry.passwords;

import java.security.SecureRandom;
import java.util.Arrays;

/**
 * Generalized wrapper for bytes we do not wish to leave in heap memory to whim of the GC.
 * 
 * @author Dave
 *
 */
public class SensitiveBytes {

	private static final SecureRandom internalSecRand = new SecureRandom();
	
	protected byte [] data;
	protected boolean alive;
	
	public SensitiveBytes(byte [] data) {
		this.data = data;
		alive=true;
	}
	
	/**
	 * Constructor be used to load random bytes of the requested length
	 *  
	 * @param rand
	 * @param length
	 */
	public SensitiveBytes(SecureRandom rand, int length) {
		data = new byte[length];
		rand.nextBytes(data);
		alive=true;
	}
	
	/**
	 * Constructor be used to self-generate cryptographic quality random bytes of the requested length
	 *  
	 * @param rand
	 * @param length
	 */
	public SensitiveBytes(int length) {
		data = new byte[length];
		internalSecRand.nextBytes(data);
		alive=true;
	}
	
	/**
	 * Add the contents of two data objects together into one (concatenate p1 and p2)
	 * @param p1
	 * @param p2
	 */
	public SensitiveBytes(SensitiveBytes p1, SensitiveBytes p2) {
		super();
		int length = p1.length()+p2.length();
		data = new byte[length];
		System.arraycopy(p1.getData(), 0, data, 0, p1.length());
		System.arraycopy(p2.getData(), 0, data, p1.length(), p2.length());
		alive=true;
	}

	public byte [] getData(){
		if(!alive) throw new RuntimeException("This instance is dead...");
		return data;
	}
	
	public void selfDestruct(){
		for(int i = 0; i<data.length; i++){
			data[i] = '\0';
		}
		alive = false;
	}
	
	public int length() {
		return data.length;
	}

	public boolean isAlive() {
		return alive;
	}
	
	public final String toString(){
		return "...";
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + (alive ? 1231 : 1237);
		result = prime * result + Arrays.hashCode(data);
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
		SensitiveBytes other = (SensitiveBytes) obj;
		if (alive != other.alive)
			return false;
		if (!Arrays.equals(data, other.data))
			return false;
		return true;
	}
	
	public static void cleanUp(byte[]array){
		for(int i = 0; i<array.length; i++){
			array[i] = '\0';
		}
	}
}
