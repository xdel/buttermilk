/*
 *  This file is part of Buttermilk
 *  Copyright 2011-2014 David R. Smith All Rights Reserved.
 *
 */
package com.cryptoregistry.ec;

import x.org.bouncycastle.crypto.params.ECDomainParameters;

/**
 * Static definitions of the various curves. These are adapted from Bouncy Castle's definitions
 * 
 * 
 * @author Dave
 *
 */
public class CurveFactory {
	
	// curves we know about from BC 1.50 - have only done the prime fields so far
	public enum CurveName {
		secp112r1, secp112r2, secp128r1, secp128r2, secp160k1,
		secp160r1, secp160r2, secp192k1, secp192r1, secp224k1,
		secp224r1, secp256k1, P224, P256, P384, P521, brainpoolP160r1;
	}
	
	public static boolean curveNameDefined(final String name){
		try {
			return getCurveForName(name) != null;
		}catch(RuntimeException x){
			return false;
		}
	}
	
	public static ECDomainParameters getCurveForName(final String name){
		switch(name){
			case "secp112r1":{
				return CurveFactory.secp112r1.createParameters();
			}
			case "secp112r2":{
				return CurveFactory.secp112r2.createParameters();
			}
			case "secp128r1":{
				return CurveFactory.secp128r1.createParameters();
			}
			case "secp128r2":{
				return CurveFactory.secp128r2.createParameters();
			}
			case "secp160k1":{
				return CurveFactory.secp160k1.createParameters();
			}
			case "secp160r1":{
				return CurveFactory.secp160r1.createParameters();
			}
			case "secp160r2":{
				return CurveFactory.secp160r2.createParameters();
			}
			case "secp192k1":{
				return CurveFactory.secp192k1.createParameters();
			}
			case "secp192r1":{
				return CurveFactory.secp192r1.createParameters();
			}
			case "secp224k1":{
				return CurveFactory.secp224k1.createParameters();
			}
			case "secp224r1":{
				return CurveFactory.secp224r1.createParameters();
			}
			case "secp256k1":{
				return CurveFactory.secp256k1.createParameters();
			}
			
			//NIST P-224
			
			case "P224":{
				return CurveFactory.p224.createParameters();
			}
			case "P-224":{
				return CurveFactory.p224Dash.createParameters();
			}
	
			
			//NIST P-256
			
			case "secp256r1":{
				return CurveFactory.secp256r1.createParameters();
			}
			case "P256":{
				return CurveFactory.p256.createParameters();
			}
			case "P-256":{
				return CurveFactory.p256Dash.createParameters();
			}
			
			//NIST P-384
			
			case "secp284r1":{
				return CurveFactory.secp384r1.createParameters();
			}
			case "P384":{
				return CurveFactory.p384.createParameters();
			}
			case "P-384":{
				return CurveFactory.p384Dash.createParameters();
			}
		
			
			//NIST P-521
			
			case "secp521r1":{
				return CurveFactory.secp521r1.createParameters();
			}
			case "P521":{
				return CurveFactory.p521.createParameters();
			}
			case "P-521":{
				return CurveFactory.p521Dash.createParameters();
			}
			
			
			case "brainpoolP160r1": {
				return CurveFactory.brainpoolP160r1.createParameters();
			}
			
			// TODO my own idea for a name but seems reasonable - these curves don't work yet
			
			/*
			case "DSTU4145.0": return dstu4145.params[0];
			case "DSTU4145.1": return dstu4145.params[1];
			case "DSTU4145.2": return dstu4145.params[2];
			case "DSTU4145.3": return dstu4145.params[3];
			case "DSTU4145.4": return dstu4145.params[4];
			case "DSTU4145.5": return dstu4145.params[5];
			case "DSTU4145.6": return dstu4145.params[6];
			case "DSTU4145.7": return dstu4145.params[7];
			case "DSTU4145.8": return dstu4145.params[8];
			case "DSTU4145.9": return dstu4145.params[9];
			*/
			// TODO add all the rest, the prime fields seem like the most secure, 
			// will add binary fields later
			
			default: throw new RuntimeException("unknown curve name: "+name);
		}
	}
	
	private static final ECParametersHolder secp112r1 = Secp112r1.instance();
	private static final ECParametersHolder secp112r2 = Secp112r2.instance();
	private static final ECParametersHolder secp128r1 = Secp128r1.instance();
	private static final ECParametersHolder secp128r2 = Secp128r2.instance();
	private static final ECParametersHolder secp160k1 = Secp160k1.instance();
	private static final ECParametersHolder secp160r1 = Secp160r1.instance();
	private static final ECParametersHolder secp160r2 = Secp160r2.instance();
	private static final ECParametersHolder secp192k1 = Secp192k1.instance();
	private static final ECParametersHolder secp192r1 = Secp192r1.instance();
	
	private static final ECParametersHolder secp224k1 = Secp224k1.instance();
	private static final ECParametersHolder secp256k1 = Secp256k1.instance();
	
	private static final ECParametersHolder secp224r1 = Secp224r1.instance();
	private static final ECParametersHolder p224 = Secp224r1.p224();
	private static final ECParametersHolder p224Dash = Secp224r1.p224Dash();
	
	private static final ECParametersHolder secp256r1 = Secp256r1.instance();
	private static final ECParametersHolder p256 = Secp256r1.p256();
	private static final ECParametersHolder p256Dash = Secp256r1.p256Dash();
	
	private static final ECParametersHolder secp384r1 = Secp384r1.instance();
	private static final ECParametersHolder p384 = Secp384r1.p384();
	private static final ECParametersHolder p384Dash = Secp384r1.p384Dash();
	
	private static final ECParametersHolder secp521r1 = Secp521r1.instance();
	private static final ECParametersHolder p521 = Secp521r1.p521();
	private static final ECParametersHolder p521Dash = Secp521r1.p521Dash();
	
	
	private static final ECParametersHolder brainpoolP160r1 = BrainpoolP160r1.instance();
	
//	private static final DSTU4145NamedCurves dstu4145 = DSTU4145NamedCurves.getInstance();
	
}
