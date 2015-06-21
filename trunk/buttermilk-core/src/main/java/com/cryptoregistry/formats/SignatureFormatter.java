/*
 *  This file is part of Buttermilk
 *  Copyright 2011-2014 David R. Smith All Rights Reserved.
 *
 */
package com.cryptoregistry.formats;

import java.io.IOException;
import java.io.StringWriter;
import java.io.Writer;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import com.cryptoregistry.signature.CryptoSignature;
import com.cryptoregistry.util.TimeUtil;
import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.JsonGenerationException;
import com.fasterxml.jackson.core.JsonGenerator;

public class SignatureFormatter {

	private List<CryptoSignature> list;

	public SignatureFormatter() {
		list = new ArrayList<CryptoSignature>();
	}
	
	public SignatureFormatter(CryptoSignature sig) {
		list = new ArrayList<CryptoSignature>();
		list.add(sig);
	}

	public SignatureFormatter(List<CryptoSignature> list) {
		super();
		this.list = list;
	}

	public void add(CryptoSignature sig) {
		list.add(sig);
	}

	public void format(JsonGenerator g, Writer writer)
			throws JsonGenerationException, IOException {
		for (CryptoSignature s : list) {

			// common stuff
			g.writeObjectFieldStart(s.getHandle());
			g.writeStringField("CreatedOn", TimeUtil.format(s.getCreatedOn()));
			g.writeStringField("SignedWith", s.getSignedWith());
			g.writeStringField("SignedBy", s.getSignedBy());
			g.writeStringField("SignatureAlgorithm", s.getSigAlg().toString());
			g.writeStringField("DigestAlgorithm", s.metadata.digestAlg);

			// does the actual key contents (possibly multiple fields)
			s.formatSignaturePrimitivesJSON(g, writer);
			
			// simplification, cleaner
			g.writeStringField("DataRefs", CryptoSignature.getDataReferenceString(s));
			
			g.writeEndObject();
		}
	}
	
	public String format(){
		return this.format(0);
	}

	public String format(int index) {
		CryptoSignature s = list.get(index);
		StringWriter writer = new StringWriter();
		JsonFactory f = new JsonFactory();
		JsonGenerator g = null;
		try {
			g = f.createGenerator(writer);
			
			g.writeStartObject();
			
			g.writeObjectFieldStart(s.getHandle());
			g.writeStringField("CreatedOn", TimeUtil.format(s.getCreatedOn()));
			g.writeStringField("SignedWith", s.getSignedWith());
			g.writeStringField("SignedBy", s.getSignedBy());
			g.writeStringField("SignatureAlgorithm", s.getSigAlg().toString());
			g.writeStringField("DigestAlgorithm", s.metadata.digestAlg);

			// does the actual key contents (possibly multiple fields)
			s.formatSignaturePrimitivesJSON(g, writer);

			// also common
			g.writeArrayFieldStart("DataRefs");
			Iterator<String> iter = s.getDataRefs().iterator();
			while (iter.hasNext()) {
				g.writeString(iter.next());
			}
			g.writeEndArray();
			g.writeEndObject();
		} catch (IOException e) {
			e.printStackTrace();
		} finally {
			try {
				g.close();
			} catch (IOException e) {
				throw new RuntimeException(e);
			}
		}

		return writer.toString();
	}

}
