package com.cryptoregistry.util;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.HashSet;
import java.util.Set;

public class DomainTLDChecker {
	
	final Set<String> tlds = new HashSet<String>();

	public DomainTLDChecker() {
		
		InputStream in = this.getClass().getResourceAsStream("/tlds-alpha-by-domain.txt");
		if(in == null){
			throw new RuntimeException("Classpath issue, apparently.");
		}
		InputStreamReader reader = new InputStreamReader(in);
		BufferedReader bin = new BufferedReader(reader);
		String line = null;
		try {
			while ((line = bin.readLine()) != null) {
				if(line.trim().startsWith("#")) continue;
				if(line.trim().equals("")) continue;
				tlds.add(line.toLowerCase().trim());
			}
		} catch (IOException e) {
			e.printStackTrace();
		}finally{
			try {
				if(in != null) in.close();
			} catch (IOException e) {}
		}
	}
	
	public boolean isPresent(String input){
		return tlds.contains(input.toLowerCase());
	}
}
