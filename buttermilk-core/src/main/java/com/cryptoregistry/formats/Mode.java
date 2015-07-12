/*
 *  This file is part of Buttermilk
 *  Copyright 2011-2014 David R. Smith All Rights Reserved.
 *
 */
package com.cryptoregistry.formats;

/**
 * Request the mode of formatting to be applied when serialization is done on this key.
 * 
 * Rather than "public" and "private" distinctions we have an alternative in "secured", "unsecured", and "for publication".
 * 
 * REQUEST_FOR_PUBLICATION will try to assure that nothing which is supposed to be confidential is released.
 * 
 * @author Dave
 *
 */
public enum Mode {
	UNSECURED('U'), REQUEST_SECURE('S'), REQUEST_FOR_PUBLICATION('P');
	
	public final char code;

	private Mode(char code) {
		this.code = code;
	}
	
	
}
