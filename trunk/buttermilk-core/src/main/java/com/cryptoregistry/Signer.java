/*
 *  This file is part of Buttermilk
 *  Copyright 2011-2014 David R. Smith All Rights Reserved.
 *
 */
package com.cryptoregistry;

/**
 * Marker for key classes which contain "private key" or confidential key contents, i.e., 
 * they can (at least potentially) make a digital signature. In some cases, like NTRU,
 * that is known to be broken so we don't support actually doing signing with that type of key, 
 * but we still use the marker interface on that key class.
 * 
 * @author Dave
 *
 */
public interface Signer {

	public void scrubPassword();
}
