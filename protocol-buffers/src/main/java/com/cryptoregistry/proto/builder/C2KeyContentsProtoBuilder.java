/*
 *  This file is part of Buttermilk
 *  Copyright 2011-2014 David R. Smith All Rights Reserved.
 *
 */
package com.cryptoregistry.proto.builder;

import com.cryptoregistry.c2.key.Curve25519KeyContents;
import com.cryptoregistry.protos.Buttermilk.C2KeyContentsProto;
import com.cryptoregistry.protos.Buttermilk.KeyMetadataProto;
import com.google.protobuf.ByteString;

/**
 * Make a proto buffer out of an C25519KeyForPublication instance. 
 * 
 * @author Dave
 *
 */
public class C2KeyContentsProtoBuilder {

	final Curve25519KeyContents keyContents;
	
	public C2KeyContentsProtoBuilder(Curve25519KeyContents keyContents) {
		this.keyContents = keyContents;
	}
	
	public C2KeyContentsProto build() {
		
		KeyMetadataProtoBuilder metaBuilder = new KeyMetadataProtoBuilder(keyContents.metadata);
		KeyMetadataProto metaProto = metaBuilder.build();
		
		C2KeyContentsProto c2Proto = C2KeyContentsProto.newBuilder()
				.setMeta(metaProto)
				.setPublicKey(ByteString.copyFrom(keyContents.publicKey.getBytes()))
				.setAgreementPrivateKey(ByteString.copyFrom(keyContents.agreementPrivateKey.getBytes()))
				.setSigningPrivateKey(ByteString.copyFrom(keyContents.signingPrivateKey.getBytes()))
				.build();
		
		return c2Proto;
		
	}
}
