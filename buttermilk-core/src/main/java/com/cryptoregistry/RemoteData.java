package com.cryptoregistry;

import java.io.File;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

public class RemoteData {

	public final List<String> urls;
	
	public RemoteData() {
		super();
		urls = new ArrayList<String>();
	}
	
	public void addURL(String url){
		urls.add(url);
	}
	
	public void addFile(File path){
		try {
			urls.add(path.toURI().toURL().toString());
		} catch (MalformedURLException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
	public void addPath(Path path){
		addFile(path.toFile());
	}
	
	public void addURL(URL url){
		addURL(url.toString());
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((urls == null) ? 0 : urls.hashCode());
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (getClass() != obj.getClass())
			return false;
		RemoteData other = (RemoteData) obj;
		if (urls == null) {
			if (other.urls != null)
				return false;
		} else if (!urls.equals(other.urls))
			return false;
		return true;
	}

	@Override
	public String toString() {
		return "RemoteData [urls=" + urls + "]";
	}

}