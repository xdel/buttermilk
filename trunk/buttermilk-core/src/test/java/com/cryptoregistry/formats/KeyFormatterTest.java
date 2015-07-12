package com.cryptoregistry.formats;

import org.junit.Assert;
import org.junit.Test;

public class KeyFormatterTest {
	
	@Test 
	public void test1() {
		
		char [] pass = {'p','a','s','s'};
		KeyFormat f = KeyFormat.securedPBKDF2(pass);
		Assert.assertNotNull(f.pbeParams.getSalt());
		Assert.assertNull(f.pbeParams.getIv());
		Assert.assertTrue(f.pbeParams.getIterations() > 0);
		Assert.assertTrue(f.encodingHint == EncodingHint.Base64url);
		
		f = KeyFormat.securedSCRYPT(pass);
		Assert.assertTrue(f.encodingHint == EncodingHint.Base64url);
		Assert.assertNotNull(f.pbeParams.getSalt());
		Assert.assertNotNull(f.pbeParams.getIv());
		Assert.assertTrue(f.pbeParams.getBlockSize_r() != -1);
		Assert.assertTrue(f.pbeParams.getCpuMemoryCost_N() != -1);
		Assert.assertTrue(f.pbeParams.getDesiredKeyLengthInBytes() != -1);
		Assert.assertTrue(f.pbeParams.getParallelization_p() != -1);
		Assert.assertTrue(f.pbeParams.getIterations() == -1);
		
	}


}
