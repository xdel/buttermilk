/*
 *  This file is part of Buttermilk
 *  Copyright 2011-2014 David R. Smith All Rights Reserved.
 *
 */
package com.cryptoregistry.proto.builder;

import com.cryptoregistry.ec.ECCustomParameters;
import com.cryptoregistry.ec.ECKeyContents;
import com.cryptoregistry.formats.FormatUtil;
import com.cryptoregistry.protos.Buttermilk.CurveDefinitionProto;
import com.cryptoregistry.protos.Buttermilk.ECKeyContentsProto;
import com.cryptoregistry.protos.Buttermilk.KeyMetadataProto;
import com.google.protobuf.ByteString;

/**
 * Make a proto buffer out of an ECKeyForPublication instance. 
 * 
 * @author Dave
 *
 */
public class ECKeyContentsProtoBuilder {

	final ECKeyContents keyContents;
	
	public ECKeyContentsProtoBuilder(ECKeyContents keyContents) {
		this.keyContents = keyContents;
	}
	
	/**
	 * Note: the encoding hint should be reasonable for encoding Q, such as base16
	 * 
	 * @return
	 */
	public ECKeyContentsProto build() {
		
		KeyMetadataProtoBuilder metaBuilder = new KeyMetadataProtoBuilder(keyContents.metadata);
		KeyMetadataProto metaProto = metaBuilder.build();
		ECKeyContentsProto.Builder ecProtoBuilder = ECKeyContentsProto.newBuilder();
		
		ecProtoBuilder.setMeta(metaProto);
		
		if(keyContents.usesNamedCurve()) {
			ecProtoBuilder.setCurveName(keyContents.curveName);
		}else{
			ECCustomParameters params = (ECCustomParameters) keyContents.customCurveDefinition;
			CurveDefinitionProtoBuilder custBuilder = new CurveDefinitionProtoBuilder(params);
			CurveDefinitionProto curveDefProto = custBuilder.build();
			ecProtoBuilder.setCurveDefinition(curveDefProto);
		}
		
		ecProtoBuilder.setQ(FormatUtil.serializeECPoint(keyContents.Q, keyContents.metadata.format.encodingHint));
		ecProtoBuilder.setD(ByteString.copyFrom(keyContents.d.toByteArray()));
		
		return ecProtoBuilder.build();
	}
}