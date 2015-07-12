/*
 *  This file is part of Buttermilk
 *  Copyright 2011-2014 David R. Smith All Rights Reserved.
 *
 */
package com.cryptoregistry.pbe;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import com.cryptoregistry.passwords.NewPassword;
import com.cryptoregistry.passwords.Password;
import com.cryptoregistry.passwords.SensitiveBytes;

/**
 * Settings are just defaults - 
 * 
 * @author Dave
 *
 */
public class PBEParamsFactory {

	public final SecureRandom rand;
	
	// SCRYPT SALT length
	public static final int SALT_LENGTH = 32;
	
	// the IV is not used with SCRYPT, but is needed for the AES algorithm used to secure the key once it is generated
	public static final int IV_LENGTH = 16; // 128 bit block size of AES 256
	
	// a reasonable iteration value
	public static final int PBKDF2_ITERATIONS = 10000;
	
	// these seem reasonable for today's hardware, do take a few seconds on my box. If you have issues please let me know
	public static final int CPU_MEMORY_COST = 1024;
	public static final int PARALLELIZATION = 64;
	
	public static final int DESIRED_KEY_LENGTH = 32;
	
	public static final PBEParamsFactory INSTANCE = new PBEParamsFactory();
	
	private PBEParamsFactory() {
		try {
			rand = SecureRandom.getInstance("SHA1PRNG");
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException(e);
		}
	}
		
	public PBEParams createPBKDF2Params(char [] passwordChars) {
		
		Password password = new NewPassword(passwordChars);
		SensitiveBytes salt = new SensitiveBytes(rand,SALT_LENGTH);
		PBEParams params = new PBEParams(PBEAlg.PBKDF2);
		params.setSalt(salt);
		params.setIterations(PBKDF2_ITERATIONS);
		params.setPassword(password);
		
		// used by Scrypt only
		params.setBlockSize_r(-1);
		params.setCpuMemoryCost_N(-1);
		params.setDesiredKeyLengthInBytes(-1);
		params.setParallelization_p(-1);
		
		// do not supply IV here = it is created in the key generation alg in the PBE class.
		
		return params;
	}
	
	public PBEParams createPBKDF2Params(int iterations, char [] passwordChars) {
		Password password = new NewPassword(passwordChars);
		SensitiveBytes salt = new SensitiveBytes(rand,SALT_LENGTH);
		PBEParams params = new PBEParams(PBEAlg.PBKDF2);
		params.setSalt(salt);
		params.setIterations(iterations);
		params.setPassword(password);
		
		// used by Scrypt only
		params.setBlockSize_r(-1);
		params.setCpuMemoryCost_N(-1);
		params.setDesiredKeyLengthInBytes(-1);
		params.setParallelization_p(-1);
		
		// do not supply IV here = it is created in the key generation alg in the PBE class.
		
		return params;
	}
	
	/**
	 * Default settings (see constants for the values)
	 * 
	 * @param passwordChars
	 * @return
	 */
	public PBEParams createScryptParams(char [] passwordChars) {
		
		Password password = new NewPassword(passwordChars);
		SensitiveBytes salt = new SensitiveBytes(rand,SALT_LENGTH);
		
		// need IV here, it is used in the key generation alg in the PBE class.
		SensitiveBytes iv = new SensitiveBytes(rand,IV_LENGTH);
		
		PBEParams params = new PBEParams(PBEAlg.SCRYPT);
		params.setIv(iv);
		params.setIterations(-1);
		params.setPassword(password);
		params.setSalt(salt);
		params.setBlockSize_r(IV_LENGTH*8);
		params.setCpuMemoryCost_N(CPU_MEMORY_COST);
		params.setDesiredKeyLengthInBytes(DESIRED_KEY_LENGTH);
		params.setParallelization_p(PARALLELIZATION);
		return params;
	}
	
	/**
	 * Custom cpuCost and parallelization can be set if desired
	 * 
	 * @param passwordChars
	 * @return
	 */
	public PBEParams createScryptParams(int cpuCost, int parallelization, char [] passwordChars) {
		
		Password password = new NewPassword(passwordChars);
		SensitiveBytes salt = new SensitiveBytes(rand,SALT_LENGTH);
		
		PBEParams params = new PBEParams(PBEAlg.SCRYPT);
		params.setIterations(-1);
		params.setPassword(password);
		params.setSalt(salt);
		params.setBlockSize_r(IV_LENGTH*8);
		params.setCpuMemoryCost_N(cpuCost);
		params.setDesiredKeyLengthInBytes(DESIRED_KEY_LENGTH);
		params.setParallelization_p(parallelization);
		return params;
	}
}
