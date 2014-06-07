package com.cryptoregistry.formats;

import java.io.IOException;
import java.io.StringWriter;
import java.io.UnsupportedEncodingException;
import java.io.Writer;

import com.cryptoregistry.c2.key.Curve25519KeyContents;
import com.cryptoregistry.pbe.ArmoredPBEResult;
import com.cryptoregistry.pbe.ArmoredPBKDF2Result;
import com.cryptoregistry.pbe.ArmoredScryptResult;
import com.cryptoregistry.pbe.PBE;
import com.cryptoregistry.pbe.PBEParams;
import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.JsonGenerationException;
import com.fasterxml.jackson.core.JsonGenerator;

class C2KeyFormatter {

	protected final Curve25519KeyContents c2Keys;
	protected final KeyFormat format;
	protected final PBEParams pbeParams;

	public C2KeyFormatter(Curve25519KeyContents c2Keys) {
		super();
		this.c2Keys = c2Keys;
		this.format = c2Keys.management.format;
		this.pbeParams = c2Keys.management.format.pbeParams;

	}

	public void formatKeys(JsonGenerator g, Writer writer) {

		try {
			switch (format.mode) {
			case OPEN: {
				formatOpen(g, format.encoding, writer);
				break;
			}
			case SEALED: {
				seal(g, format.encoding, writer);
				break;
			}
			case FOR_PUBLICATION: {
				formatForPublication(g, format.encoding, writer);
				break;
			}
			default:
				throw new RuntimeException("Unknown mode");
			}
		}catch(Exception x){
			throw new RuntimeException(x);
		}
		
	}

	protected void seal(JsonGenerator g, Encoding enc, Writer writer)
			throws JsonGenerationException, IOException {

		String plain = formatItem(enc, c2Keys);
		ArmoredPBEResult result;
		try {
			byte[] plainBytes = plain.getBytes("UTF-8");
			PBE pbe0 = new PBE(pbeParams);
			result = pbe0.encrypt(plainBytes);
		} catch (UnsupportedEncodingException e) {
			throw new RuntimeException(e);
		}

		g.writeObjectFieldStart(c2Keys.management.handle);
		g.writeStringField("KeyData.Type", "Curve25519");
		g.writeStringField("KeyData.PBEAlgorithm", pbeParams.getAlg()
				.toString());
		g.writeStringField("KeyData.EncryptedData", result.base64Enc);
		g.writeStringField("KeyData.PBESalt", result.base64Salt);

		if (result instanceof ArmoredPBKDF2Result) {
			// specific to PBKDF2
			g.writeStringField("KeyData.Iterations",
					String.valueOf(((ArmoredPBKDF2Result) result).iterations));

		} else if (result instanceof ArmoredScryptResult) {
			// specific to Scrypt
			g.writeStringField("KeyData.IV",
					((ArmoredScryptResult) result).base64IV);
			g.writeStringField("KeyData.BlockSize",
					String.valueOf(((ArmoredScryptResult) result).blockSize));
			g.writeStringField("KeyData.CpuMemoryCost", String
					.valueOf(((ArmoredScryptResult) result).cpuMemoryCost));
			g.writeStringField("KeyData.Parallelization", String
					.valueOf(((ArmoredScryptResult) result).parallelization));
		}
		g.writeEndObject();

	}

	protected void formatOpen(JsonGenerator g, Encoding enc, Writer writer)
			throws JsonGenerationException, IOException {

		g.writeObjectFieldStart(c2Keys.management.handle);
		g.writeStringField("Encoding", Encoding.Base64url.toString());
		g.writeStringField("P", c2Keys.publicKey.getBase64UrlEncoding());
		g.writeStringField("s", c2Keys.signingPrivateKey.getBase64UrlEncoding());
		g.writeStringField("k",
				c2Keys.agreementPrivateKey.getBase64UrlEncoding());
		g.writeEndObject();
	}

	protected void formatForPublication(JsonGenerator g, Encoding enc,
			Writer writer) throws JsonGenerationException, IOException {

		g.writeObjectFieldStart(c2Keys.management.handle);
		g.writeStringField("Encoding", Encoding.Base64url.toString());
		g.writeStringField("P", c2Keys.publicKey.getBase64UrlEncoding());
		g.writeEndObject();
	}

	private String formatItem(Encoding enc, Curve25519KeyContents item) {
		StringWriter privateDataWriter = new StringWriter();
		JsonFactory f = new JsonFactory();
		JsonGenerator g = null;
		try {
			g = f.createGenerator(privateDataWriter);
			g.useDefaultPrettyPrinter();
			g.writeStartObject();
			g.writeObjectFieldStart(c2Keys.management.handle);
			g.writeStringField("Encoding", Encoding.Base64url.toString());
			g.writeStringField("P", c2Keys.publicKey.getBase64UrlEncoding());
			g.writeStringField("s",
					c2Keys.signingPrivateKey.getBase64UrlEncoding());
			g.writeStringField("k",
					c2Keys.agreementPrivateKey.getBase64UrlEncoding());
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

		return privateDataWriter.toString();
	}

}