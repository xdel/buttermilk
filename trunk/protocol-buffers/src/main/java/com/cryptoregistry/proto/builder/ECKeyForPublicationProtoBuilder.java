/*
 *  This file is part of Buttermilk
 *  Copyright 2011-2014 David R. Smith All Rights Reserved.
 *
 */
package com.cryptoregistry.proto.builder;

import com.cryptoregistry.ec.ECCustomParameters;
import com.cryptoregistry.ec.ECKeyForPublication;
import com.cryptoregistry.formats.EncodingHint;
import com.cryptoregistry.formats.FormatUtil;
import com.cryptoregistry.protos.Buttermilk.CurveDefinitionProto;
import com.cryptoregistry.protos.Buttermilk.ECKeyForPublicationProto;
import com.cryptoregistry.protos.Buttermilk.KeyMetadataProto;

/**
 * Make a proto buffer out of an ECKeyForPublication instance. 
 * 
 * @author Dave
 *
 */
public class ECKeyForPublicationProtoBuilder {

	final ECKeyForPublication keyContents;
	
	public ECKeyForPublicationProtoBuilder(ECKeyForPublication keyContents) {
		this.keyContents = keyContents;
	}
	
	/**
	 * Assume Q is encoded in Hex (Base16)
	 * 
	 * @return
	 */
	public ECKeyForPublicationProto build() {
		
		KeyMetadataProtoBuilder metaBuilder = new KeyMetadataProtoBuilder(keyContents.metadata);
		KeyMetadataProto metaProto = metaBuilder.build();
		ECKeyForPublicationProto.Builder ecProtoBuilder = ECKeyForPublicationProto.newBuilder();
		
		ecProtoBuilder.setMeta(metaProto);
		
		if(keyContents.usesNamedCurve()) {
			ecProtoBuilder.setCurveName(keyContents.curveName);
		}else{
			ECCustomParameters params = (ECCustomParameters) keyContents.customCurveDefinition;
			CurveDefinitionProtoBuilder custBuilder = new CurveDefinitionProtoBuilder(params);
			CurveDefinitionProto curveDefProto = custBuilder.build();
			ecProtoBuilder.setCurveDefinition(curveDefProto);
		}
		
		ecProtoBuilder.setQ(FormatUtil.serializeECPoint(keyContents.Q, EncodingHint.Base16));
		
		return ecProtoBuilder.build();
	}
}