/*
 *  This file is part of Buttermilk
 *  Copyright 2011-2014 David R. Smith All Rights Reserved.
 *
 */
package com.cryptoregistry.btls;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.Socket;
import java.net.SocketAddress;
import java.net.SocketException;
import java.nio.channels.SocketChannel;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import com.cryptoregistry.btls.handshake.init.AutoloadEvent;
import com.cryptoregistry.btls.handshake.init.AutoloadListener;
import com.cryptoregistry.btls.handshake.kem.BaseKeyExchangeModule;
import com.cryptoregistry.btls.handshake.kem.KeyExchangeEvent;
import com.cryptoregistry.btls.handshake.kem.KeyExchangeListener;
import com.cryptoregistry.btls.io.FrameInputStream;
import com.cryptoregistry.btls.io.FrameOutputStream;
import com.cryptoregistry.symmetric.SymmetricKeyContents;

/**
 * Package protected, use ClientSocketSecureConnector to get a secure client socket
 * 
 * @author Dave
 *
 */

class SecureSocketWrapper extends Socket implements KeyExchangeListener, AutoloadListener {

	static final Logger logger = LogManager.getLogger(SecureSocketWrapper.class.getName());
	
	protected Socket client;
	protected FrameOutputStream fout;
	protected FrameInputStream fin;

	protected SymmetricKeyContents contents;
	
	
	public SecureSocketWrapper(Socket client) {
		this.client = client;
	}

	@Override
	public void connect(SocketAddress endpoint) throws IOException {

		client.connect(endpoint);
	}

	@Override
	public void connect(SocketAddress endpoint, int timeout) throws IOException {

		client.connect(endpoint, timeout);
	}

	@Override
	public void bind(SocketAddress bindpoint) throws IOException {

		client.bind(bindpoint);
	}

	@Override
	public InetAddress getInetAddress() {

		return client.getInetAddress();
	}

	@Override
	public InetAddress getLocalAddress() {

		return client.getLocalAddress();
	}

	@Override
	public int getPort() {

		return client.getPort();
	}

	@Override
	public int getLocalPort() {

		return client.getLocalPort();
	}

	@Override
	public SocketAddress getRemoteSocketAddress() {

		return client.getRemoteSocketAddress();
	}

	@Override
	public SocketAddress getLocalSocketAddress() {

		return client.getLocalSocketAddress();
	}

	@Override
	public SocketChannel getChannel() {

		return client.getChannel();
	}

	@Override
	public InputStream getInputStream() throws IOException {

		return fin;
	}

	@Override
	public OutputStream getOutputStream() throws IOException {

		return fout;
	}

	@Override
	public void setTcpNoDelay(boolean on) throws SocketException {

		client.setTcpNoDelay(on);
	}

	@Override
	public boolean getTcpNoDelay() throws SocketException {

		return client.getTcpNoDelay();
	}

	@Override
	public void setSoLinger(boolean on, int linger) throws SocketException {

		client.setSoLinger(on, linger);
	}

	@Override
	public int getSoLinger() throws SocketException {

		return client.getSoLinger();
	}

	@Override
	public void sendUrgentData(int data) throws IOException {

		client.sendUrgentData(data);
	}

	@Override
	public void setOOBInline(boolean on) throws SocketException {

		client.setOOBInline(on);
	}

	@Override
	public boolean getOOBInline() throws SocketException {

		return client.getOOBInline();
	}

	@Override
	public synchronized void setSoTimeout(int timeout) throws SocketException {

		client.setSoTimeout(timeout);
	}

	@Override
	public synchronized int getSoTimeout() throws SocketException {

		return client.getSoTimeout();
	}

	@Override
	public synchronized void setSendBufferSize(int size) throws SocketException {

		client.setSendBufferSize(size);
	}

	@Override
	public synchronized int getSendBufferSize() throws SocketException {

		return client.getSendBufferSize();
	}

	@Override
	public synchronized void setReceiveBufferSize(int size)
			throws SocketException {

		client.setReceiveBufferSize(size);
	}

	@Override
	public synchronized int getReceiveBufferSize() throws SocketException {

		return client.getReceiveBufferSize();
	}

	@Override
	public void setKeepAlive(boolean on) throws SocketException {

		client.setKeepAlive(on);
	}

	@Override
	public boolean getKeepAlive() throws SocketException {

		return client.getKeepAlive();
	}

	@Override
	public void setTrafficClass(int tc) throws SocketException {

		client.setTrafficClass(tc);
	}

	@Override
	public int getTrafficClass() throws SocketException {

		return client.getTrafficClass();
	}

	@Override
	public void setReuseAddress(boolean on) throws SocketException {
		client.setReuseAddress(on);
	}

	@Override
	public boolean getReuseAddress() throws SocketException {
		return client.getReuseAddress();
	}

	@Override
	public synchronized void close() throws IOException {
		if(!client.isClosed()){
			fout.close();
			//now close the socket
			logger.info("closing "+this);
			client.close();
		}
	}

	@Override
	public void shutdownInput() throws IOException {
		client.shutdownInput();
	}

	@Override
	public void shutdownOutput() throws IOException {
		client.shutdownOutput();
	}

	@Override
	public String toString() {
		return client.toString();
	}

	@Override
	public boolean isConnected() {
		return client.isConnected();
	}

	@Override
	public boolean isBound() {
		return client.isBound();
	}

	@Override
	public boolean isClosed() {
		return client.isClosed();
	}

	@Override
	public boolean isInputShutdown() {
		return client.isInputShutdown();
	}

	@Override
	public boolean isOutputShutdown() {
		return client.isOutputShutdown();
	}

	@Override
	public void setPerformancePreferences(int connectionTime, int latency, int bandwidth) {
		client.setPerformancePreferences(connectionTime, latency, bandwidth);
	}

	/**
	 * Once the key exchange has completed, we will get alerted to the shared secret key
	 * 
	 */
	@Override
	public void keyExchangeCompleted(KeyExchangeEvent evt) {
		logger.trace("Key exchange completed, setting streams...");
		contents = evt.getContents();
		try {
			fin = new FrameInputStream(client.getInputStream(), contents.getBytes());
			fout = new FrameOutputStream(client.getOutputStream(), contents.getBytes());
		} catch (IOException e) {
			e.printStackTrace();
		}
		
	}

	/**
	 * The autoloader will set various modules based on the handshake protocol. Once it has
	 * set the KEM, we need to listen to it to get the secret key generated by the key exchange. 
	 * 
	 */
	@Override
	public void autoloadCompleted(AutoloadEvent evt) {
		logger.trace("autoload completed, setting key exchange listener dynamically");
		BaseKeyExchangeModule mod = evt.getHandshake().getKem();
		mod.addKeyExchangeListener(this);
	}

}
