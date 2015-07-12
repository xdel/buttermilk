/*
 *  This file is part of Buttermilk
 *  Copyright 2011-2014 David R. Smith All Rights Reserved.
 *
 */
package com.cryptoregistry.formats;

/**
 * <p>Request the mode of formatting to be applied when serialization is done on this key.</p>
 * 
 * <p>Rather than "public" and "private" distinctions we have an alternative in "secured", "unsecured", and "for publication".</p>
 * 
 * <p>REQUEST_FOR_PUBLICATION will try to assure that nothing which is supposed to be confidential is released during serialization.</p>
 * 
 * @author Dave
 * @see KeyFormat
 */
public enum Mode {
	UNSECURED('U'), REQUEST_SECURE('S'), REQUEST_FOR_PUBLICATION('P');
	
	public final char code;

	private Mode(char code) {
		this.code = code;
	}
	
	
}
