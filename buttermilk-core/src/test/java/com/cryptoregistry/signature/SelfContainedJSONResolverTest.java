package com.cryptoregistry.signature;

import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;

import org.junit.Assert;
import org.junit.Test;

public class SelfContainedJSONResolverTest {

	@Test
	public void test0() {
		InputStream in = this.getClass().getResourceAsStream("/chinese-eyes.json");
		SelfContainedJSONResolver resolver = new SelfContainedJSONResolver(in);
		resolver.walk();
		try {
			
			// full keys
			String val = resolver.resolve("d35da09a-6195-4c3d-a37a-8da5cbc26be9:contactType");
			Assert.assertEquals(val, "Person");
			val = resolver.resolve("d35da09a-6195-4c3d-a37a-8da5cbc26be9:GivenName.0");
			Assert.assertEquals(val, "Dave");
			
			val = resolver.resolve("a06fc9cd-bcd6-45cc-b580-15ce5380a061:Copyright");
			Assert.assertEquals(val, "Copyright 2015 by David R. Smith. All Rights Reserved");
			
			val = resolver.resolve("496d00c4-bbe4-467c-9f76-461f7c9589c6:KeyAlgorithm");
			Assert.assertEquals(val, "Curve25519");
			
			val = resolver.resolve("2be06bce-147d-413f-b59a-d052917bc39c:v");
			Assert.assertEquals(val, "XmouiCmxeN06RkL5LECKHAGdmNqFeXkrwaCCyF0OXg8=");
			
			List<String> list = new ArrayList<String>();
			list.add("d35da09a-6195-4c3d-a37a-8da5cbc26be9:contactType");
			list.add(".Country");
			Assert.assertTrue(resolver.resolve(list).size()==2);
			
		} catch (RefNotFoundException e) {
			Assert.fail();
		}
	}
	
	@Test
	public void test1() {
		InputStream in = this.getClass().getResourceAsStream("/keys.test.json");
		SelfContainedJSONResolver resolver = new SelfContainedJSONResolver(in);
		resolver.walk();
		try {
			
			// full keys
			String val = resolver.resolve("70f85718-63c9-473e-9cb0-2ba61b874a00:Q");
			Assert.assertEquals(val, "AJXIf88iXVU6Q1L4lt2pwlxuR0CFMt9AOs8XcJ4oKxQU,ANLDowvpMLjiY8DGAPP9Uheyr7keQcQL4SuGvbzUNJbX");
			val = resolver.resolve("70f85718-63c9-473e-9cb0-2ba61b874a00:CurveName");
			Assert.assertEquals(val, "P-256");
			
		
			List<String> list = new ArrayList<String>();
			list.add("70f85718-63c9-473e-9cb0-2ba61b874a00:Q");
			list.add(".CurveName");
			Assert.assertTrue(resolver.resolve(list).size()==2);
			Assert.assertTrue(resolver.resolve(list).get(1).equals("P-256"));
			
		} catch (RefNotFoundException e) {
			Assert.fail();
		}
	}

}
