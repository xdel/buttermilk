package com.cryptoregistry.proto.frame;

import java.io.IOException;
import java.io.OutputStream;

/**
 * Useful utility methods for writing to a stream
 * 
 * @author Dave
 *
 */
public class OutputFrameBase {

	public final void writeInt(OutputStream out, int v) throws IOException {
        out.write((v >>> 24) & 0xFF);
        out.write((v >>> 16) & 0xFF);
        out.write((v >>>  8) & 0xFF);
        out.write((v >>>  0) & 0xFF);
    }
	
	public final void writeByte(OutputStream out, int v) throws IOException {
        out.write(v & 0xFF);
    }

}