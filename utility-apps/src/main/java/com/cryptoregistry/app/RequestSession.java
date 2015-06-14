package com.cryptoregistry.app;

import java.io.File;
import java.io.IOException;

public class RequestSession {
	
	int counter;
	final File parentPath;

	public RequestSession(File parentPath) {
		this.parentPath = parentPath;
		counter = scan()+1;
	}
	
	public File currentPath() {
		File path = new File(parentPath, String.valueOf(counter));
		try {
			System.err.println("Current path ="+path.getCanonicalPath());
		} catch (IOException e) {}
		return path;
	}
	
	private int scan() {
		if(parentPath == null || !parentPath.exists()) return 0;
		
		int highestValue = 0;
		File[] list = parentPath.listFiles();
		for(File f: list){
			if(f.isDirectory()){
				String name = f.getName();
				try {
					int value = Integer.parseInt(name);
					if(value > highestValue) highestValue = value;
				}catch(NumberFormatException x){
					// not a number name, move on
				}
			}
		}
		
		return highestValue;
	}
	

}
