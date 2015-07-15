package com.cryptoregistry.utility.app;

import java.io.IOException;
import java.security.SecureRandom;

import net.iharder.Base64;
import x.org.bouncycastle.util.encoders.Hex;

import com.cryptoregistry.util.CmdLineParser;
import com.cryptoregistry.util.CmdLineParser.Option;
import com.cryptoregistry.util.CmdLineParser.OptionException;
import com.cryptoregistry.util.FileUtil;
import com.cryptoregistry.util.ShowHelpUtil;

public class RandomBytesApp {

	final static SecureRandom rand = new SecureRandom();

	public static void main(String[] argv) {

		CmdLineParser parser = new CmdLineParser();
		Option<String> fileOpt = parser.addStringOption('f', "file");
		Option<Integer> lengthOpt = parser.addIntegerOption('l', "length");
		// Option<Integer> countOpt = parser.addIntegerOption('c', "count");
		Option<String> encodingOpt = parser.addStringOption('e', "encoding");

		try {

			if (argv.length > 0) {
				parser.parse(argv);

				String filePath = parser.getOptionValue(fileOpt);
				int length = parser.getOptionValue(lengthOpt, 32);
				if (length < 1)
					throw new RuntimeException("count must be greater than 1");

				FileUtil.ARMOR armor = FileUtil.ARMOR.valueOf(parser
						.getOptionValue(encodingOpt,
								FileUtil.ARMOR.base64url.toString()));

				byte[] data = new byte[length];
				rand.nextBytes(data);

				if (filePath != null) {

					byte[] bytes = null;
					switch (armor) {
					case hex:
					case base16:
						bytes = Hex.encode(data);
						FileUtil.writeFile(filePath, new String(bytes, "UTF-8").toUpperCase());
						break;
					case base64:
						FileUtil.writeFile(filePath, Base64.encodeBytes(data));
						break;
					case base64url:
						FileUtil.writeFile(filePath, 
								Base64.encodeBytes(data, Base64.URL_SAFE));
						break;
					case none:
						FileUtil.writeFile(filePath, data);
						break;
					}

					

				} else {

					switch (armor) {
					case hex:
					case base16:
						System.out.println(new String(Hex.encode(data), "UTF-8").toUpperCase());
						break;
					case base64:
						System.out.println(Base64.encodeBytes(data));
						break;
					case base64url:
						System.out.println(Base64.encodeBytes(data, Base64.URL_SAFE));
						break;
					default:
						break;
					}

				}
			} else {
				ShowHelpUtil.showHelp("/randombytes-help-message.txt");
			}

		} catch (OptionException e) {
			e.printStackTrace();
		} catch (IOException x) {
			x.printStackTrace();
		}

	}

}
