package com.cyptoregistry.handle;

import junit.framework.Assert;

import org.junit.Test;

import com.cryptoregistry.handle.CryptoHandle;
import com.cryptoregistry.handle.DomainNameHandle;
import com.cryptoregistry.handle.Handle;
import com.cryptoregistry.handle.SentenceHandle;
import com.cryptoregistry.handle.UUIDHandle;

public class HandleTest {

	@Test
	public void test0() {
		
		// domain names
		Handle h = CryptoHandle.parseHandle("facebook.com");
		Assert.assertTrue(h.validate());
		Assert.assertTrue(h instanceof DomainNameHandle);
		h = CryptoHandle.parseHandle("facebook.com.au");
		Assert.assertTrue(h.validate());
		Assert.assertTrue(h instanceof DomainNameHandle);
		h = CryptoHandle.parseHandle("something.diamonds");
		Assert.assertTrue(h.validate());
		Assert.assertTrue(h instanceof DomainNameHandle);
		
		h = CryptoHandle.parseHandle("社会主义 吮吸");
		Assert.assertTrue(h.validate());
		Assert.assertTrue(h instanceof SentenceHandle);
		
		h = CryptoHandle.parseHandle("ba80f000-d054-11e4-8477-0002a5d5c51b");
		Assert.assertTrue(h.validate());
		Assert.assertTrue(h instanceof UUIDHandle);
		
		
	
	}

}
