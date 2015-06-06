package com.cryptoregistry;

import org.junit.Assert;
import org.junit.Test;

public class CryptoContactTest {

	@Test
	public void test0() {
		CryptoContact c = new CryptoContact();
		c.add("Address.0", "Unit 1");
		c.add("Address.1", "1714 Roberts Ct.");
		
		String f = c.formatJSON();
		Assert.assertNotNull(f);
		
	}

}
