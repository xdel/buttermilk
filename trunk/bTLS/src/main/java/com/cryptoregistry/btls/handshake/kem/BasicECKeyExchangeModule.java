/*
 *  This file is part of Buttermilk
 *  Copyright 2011-2014 David R. Smith All Rights Reserved.
 *
 */
package com.cryptoregistry.btls.handshake.kem;

import java.io.IOException;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import com.cryptoregistry.btls.BTLSProtocol;
import com.cryptoregistry.btls.handshake.Handshake;
import com.cryptoregistry.btls.handshake.UnexpectedCodeException;
import com.cryptoregistry.client.security.SuitableMatchFailedException;
import com.cryptoregistry.client.storage.SingleResultCriteria;
import com.cryptoregistry.client.storage.SingleResult;
import com.cryptoregistry.ec.CryptoFactory;
import com.cryptoregistry.ec.ECKeyForPublication;
import com.cryptoregistry.ec.ECKeyContents;
import com.cryptoregistry.proto.frame.btls.ECKeyForPublicationOutputFrame;
import com.cryptoregistry.proto.frame.btls.HelloOutputFrame;
import com.cryptoregistry.proto.reader.ECKeyForPublicationProtoReader;
import com.cryptoregistry.proto.reader.Hello;
import com.cryptoregistry.proto.reader.HelloProtoReader;
import com.cryptoregistry.protos.Buttermilk.ECKeyForPublicationProto;
import com.cryptoregistry.protos.Buttermilk.HelloProto;
import com.cryptoregistry.symmetric.SymmetricKeyContents;
import com.cryptoregistry.symmetric.SymmetricKeyMetadata;
import com.google.protobuf.ByteString;

/**
 * A concrete KEM implementation for Elliptic Curve Handshakes. 
 * 
 * @author Dave
 *
 */
public class BasicECKeyExchangeModule extends BaseKEM {
	
	static final Logger logger = LogManager.getLogger(BasicECKeyExchangeModule.class.getName());

	// container reference
	Handshake handshake;
	
	private ECKeyForPublication localKey;
	private ECKeyForPublication remoteKey;
	
	private SymmetricKeyContents resultKey;
	
	public BasicECKeyExchangeModule(Handshake handshake) {
		super();
		this.handshake = handshake;
	}

	/**
	 * Exchange hello messages and peer public keys if required
	 */
	@Override
	public boolean exchange() throws ExchangeFailedException, UnexpectedCodeException {
		
		if(handshake.isServer()){
			//server mode
				
				// 1.0 read the client hello
				int subcode = consumeStartOfFrame();
				if(subcode != BTLSProtocol.CLIENT_HELLO) throw new UnexpectedCodeException(subcode);
				Hello hello = readHello();
				logger.trace("Server got client's hello: "+hello);
				
				SingleResult remote = new SingleResult();
				try {
					// 1.1a use cached key as mentioned in hello
					handshake.getDs().getViews().get(hello.keyHandle, remote);
					remoteKey = (ECKeyForPublication) remote.result;
					logger.trace("Server found client's cached key: "+remoteKey);
					
				} catch (SuitableMatchFailedException e) {
					
					logger.trace("Server failed to find a suitable match for key mentioned in hello...");
					logger.trace("requesting client to send published key...");
					// 1.1b no match found, request client to send published key
					writeSendKeyFrame();
					logger.trace("requested client to send published key...");
					
					// 1.2 - read client's remote key
					if(consumeStartOfFrame() == BTLSProtocol.SENDING_KEY){
						logger.trace("Server starting to read client's peer-supplied key...");
						remoteKey = readECKeyForPublication();
						logger.trace("Server completed reading client's peer-supplied key...");
					}
				}
				
				// with EC, we need the curveName or curveDefinition
				
				String curveName = remoteKey.curveName;
				if(curveName == null){
					throw new RuntimeException("This KEM does not handle custom curves - yet.");
				}
				
				logger.trace("Server getting localKey from store...");
				// needed for both client and server - get our local key of correct type and curveName
				SingleResultCriteria c = null;
				try {
					c = SingleResultCriteria.ec(curveName);
					handshake.getDs().getViews().get(c);
					localKey = (ECKeyContents) c.result.getResult();
				} catch (SuitableMatchFailedException e1) {
					throw new RuntimeException("No matching local key available: "+c);
				}
				logger.trace("Server got localKey from store: "+localKey);
				
				
				logger.trace("Server starting to build symmetric key...");
				buildKey();
				logger.trace("Server finished building symmetric key...");
				
				// OK, signal KEY_RECEIVED
				logger.trace("server sending KEY_RECEIVED frame...");
				writeKeyResolvedFrame();
				logger.trace("server sent KEY_RECEIVED frame...");
				
				
				// 1.3 - send SERVER_HELLO frame
				logger.trace("Server sending SERVER_HELLO...");
				HelloOutputFrame frame = new HelloOutputFrame(
						BTLSProtocol.HANDSHAKE, 
						BTLSProtocol.SERVER_HELLO,
						handshake.getDs().getRegHandle(),
						localKey.getHandle());
				frame.writeFrame(handshake.getDout());
				logger.trace("Server sent SERVER_HELLO...");
				
				// 1.4 client will either request the key to be sent or signal KEY_RESOLVED
				
				subcode = consumeStartOfFrame();
				if(subcode == BTLSProtocol.KEY_RESOLVED){
					logger.trace("Server got KEY_RESOLVED from client...");
				} else if(subcode == BTLSProtocol.SEND_KEY) {
					
					logger.trace("Server sending published key to client...");
					// ok, send the client our local key
				
					ECKeyForPublicationOutputFrame ecframe = new ECKeyForPublicationOutputFrame(
							BTLSProtocol.HANDSHAKE,
							BTLSProtocol.SENDING_KEY,
							(ECKeyContents)localKey);
					ecframe.writeFrame(handshake.getDout());
					
					logger.trace("Server sent published key to client..."+localKey.getMetadata().getHandle());
					
					// client will now signal KEY_RESOLVED
					subcode = consumeStartOfFrame();
					
					if(subcode == BTLSProtocol.KEY_RESOLVED) {
						logger.trace("Server got KEY_RESOLVED signal from client...");
					}
					
					logger.trace("Server starting to build symmetric key...");
					buildKey();
					logger.trace("Server finished building symmetric key...");
					
				}
			
		}else{
			// client mode
			
			logger.trace("Client getting localKey from store...");
			// needed for both client and server - get our local key of correct type and curveName
			SingleResultCriteria c = null;
			try {
				c = SingleResultCriteria.ec(null); // will get the first available EC Key
				handshake.getDs().getViews().get(c);
				localKey = (ECKeyContents) c.result.getResult();
			} catch (SuitableMatchFailedException e1) {
				throw new RuntimeException("No matching local key available: "+c);
			}
			logger.trace("Server got localKey from store: "+localKey);
			
			String regHandle = handshake.getDs().getRegHandle();
			
			// 1.0 send the Hello Frame
			HelloOutputFrame frame = new HelloOutputFrame(
					BTLSProtocol.HANDSHAKE, 
					BTLSProtocol.CLIENT_HELLO,
					regHandle,
					localKey.getHandle());
			frame.writeFrame(handshake.getDout());
			
			logger.trace("Client sent HelloOutputFrame..."+regHandle+", "+localKey.getHandle());
			
			// 1.1 server may now request to be sent the client's published key, or signal KEY_RESOLVED
			
			int subcode = consumeStartOfFrame();
				
				if(subcode == BTLSProtocol.KEY_RESOLVED) {
					logger.trace("Client got KEY_RESOLVED from Server...");
				} else if(subcode == BTLSProtocol.SEND_KEY) {
					
					logger.trace("Client got SEND_KEY from Server...");
					logger.trace("Client sending local key: "+localKey.getMetadata().getHandle());
					// ok, send the server our local key
					ECKeyForPublicationOutputFrame ecframe = new ECKeyForPublicationOutputFrame(
							BTLSProtocol.HANDSHAKE,
							BTLSProtocol.SENDING_KEY,
							localKey);
					ecframe.writeFrame(handshake.getDout());
					logger.trace("Client key sent to server...");
					
					// server will now signal EXCHANGE SATISFIED
					
					subcode = consumeStartOfFrame();
				
					if(subcode == BTLSProtocol.KEY_RESOLVED) {
						logger.trace("Client consumes Server's KEY_RESOLVED...");
					}else {
						logger.error("Client signals problem...did not get key...");
					}
				}
				
				// Server's situation now resolved, will send us his SERVER_HELLO
				
				Hello hello = null;
				subcode = consumeStartOfFrame();
				if(subcode != BTLSProtocol.SERVER_HELLO){
					logger.error("Expecting Server Hello, got "+subcode);
				}else{
					hello = readHello();
				}
				
				SingleResult remote = new SingleResult();
				try {
					// 1.1a use cached key as mentioned in hello
					handshake.getDs().getViews().get(hello.keyHandle, remote);
					remoteKey = (ECKeyForPublication) remote.result;
					logger.trace("Client found server's cached key: "+remoteKey);
					
				} catch (SuitableMatchFailedException e) {
					
					logger.trace("Client failed to find a suitable match for key mentioned in hello...");
					logger.trace("requesting server to send published key...");
					// 1.1b no match found, request client to send published key
					writeSendKeyFrame();
					logger.trace("requested server to send published key...");
					
					// 1.2 - read server's remote key
					if(consumeStartOfFrame() == BTLSProtocol.SENDING_KEY){
						logger.trace("Client starting to read server's published key...");
						remoteKey = readECKeyForPublication();
						logger.trace("Client completed reading server's published key...");
					}
				}
				
				this.writeKeyResolvedFrame();
				
				logger.trace("Client starting to build symmetric key...");
				buildKey();
				logger.trace("Client finished building symmetric key...");
				
		}
		
		return true;

	}
	
	/**
	 * Read a frame with a HelloProto (a registration handle and a key handle)
	 * 
	 * @return
	 * @throws UnexpectedCodeException 
	 */
	protected Hello readHello() throws UnexpectedCodeException{
		try {
			int sz = handshake.readShort16(); 
			byte [] b = new byte[sz];
			handshake.readFully(b, 0, sz);
			HelloProto proto = HelloProto.parseFrom(ByteString.copyFrom(b));
			HelloProtoReader reader = new HelloProtoReader(proto);
			return reader.read();
		} catch (IOException e) {
			throw new RuntimeException(e);
		}
	}
	
	/**
	 * contentType = BTLSProtocol.HANDSHAKE
	 * subcode = BTLSProtocol.SEND_KEY
	 * 
	 * @param out
	 */
	protected void writeSendKeyFrame(){
		try {
			handshake.writeByte((byte)BTLSProtocol.HANDSHAKE);
			handshake.writeShort(BTLSProtocol.SEND_KEY);
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
	
	/**
	 * contentType = BTLSProtocol.HANDSHAKE
	 * subcode = BTLSProtocol.SERVER_READY
	 * 
	 * @param out
	 */
	protected void writeKeyResolvedFrame(){
		try {
			handshake.writeByte((byte)BTLSProtocol.HANDSHAKE);
			handshake.writeShort(BTLSProtocol.KEY_RESOLVED);
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
	
	protected ECKeyForPublication readECKeyForPublication(){
		try {
			int sz = handshake.readShort16(); 
			byte [] b = new byte[sz];
			handshake.readFully(b, 0, sz);
			ECKeyForPublicationProto proto = ECKeyForPublicationProto.parseFrom(ByteString.copyFrom(b));
			ECKeyForPublicationProtoReader reader = new ECKeyForPublicationProtoReader(proto);
			return reader.read();
		} catch (IOException e) {
			throw new RuntimeException(e);
		}
	}
	
	/**
	 * The bytes from the key agreement are run through a SHA256 digest and stored in a Symmetric Key container.
	 * If resultKey is non-null, this method returns immediately so we don't overwrite a key
	 * 
	 */
	protected void buildKey() {
		if(resultKey != null) return;
		ECKeyContents localContents = (ECKeyContents)localKey;
		byte [] key = CryptoFactory.INSTANCE.keyAgreement(localContents, this.remoteKey);
		resultKey = new SymmetricKeyContents(SymmetricKeyMetadata.createUnsecure(), key);
		for(KeyExchangeListener l: exchangeListeners){
			l.secretExchangeCompleted(new KeyExchangeEvent(this, resultKey));
		}
	}

	public SymmetricKeyContents getResultKey() {
		return resultKey;
	}
	
	/**
	 * Consume the first byte of a frame, and return the next two bytes as the subcode represented by an integer
	 * 
	 * @return
	 * @throws ExchangeFailedException
	 */
	private int consumeStartOfFrame() throws ExchangeFailedException {
		int code = -1;
		try {
			code = handshake.readByte();
			if(code == -1) throw new ExchangeFailedException("Got -1 from readByte...");
			if(code != BTLSProtocol.HANDSHAKE) {
				if(code == BTLSProtocol.ALERT){
					logger.error("Got an alert!");
				}else if(code == BTLSProtocol.HEARTBEAT){
					logger.error("Got a heartbeat!");
				}
			}else{
				// handshake, return subcode
				int subcode = handshake.readShort16();
				return subcode;
			}
		} catch (IOException e) {
			e.printStackTrace();
		}	
		
		return -1;
	}
	
}
