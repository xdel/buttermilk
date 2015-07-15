/*
 *  This file is part of Buttermilk
 *  Copyright 2011-2014 David R. Smith All Rights Reserved.
 *
 */
package com.cryptoregistry.utility.app;

import java.io.IOException;

import net.iharder.Base64;
import x.org.bouncycastle.util.encoders.Hex;

import com.cryptoregistry.util.CmdLineParser;
import com.cryptoregistry.util.CmdLineParser.Option;
import com.cryptoregistry.util.CmdLineParser.OptionException;
import com.cryptoregistry.util.FileUtil;
import com.cryptoregistry.util.ShowHelpUtil;
import com.cryptoregistry.util.entropy.TresBiEntropy;
import com.cryptoregistry.util.entropy.TresBiEntropy.Result;

public class BiEntropyApp {

	public static final void main(String[] argv) {
		
		CmdLineParser parser = new CmdLineParser();
		Option<String> fileOpt = parser.addStringOption('f', "file");
		Option<String> argOpt = parser.addStringOption('a', "arg");
		Option<String> encodingOpt = parser.addStringOption('e', "encoding");
		
		try {
			parser.parse(argv);
			
			String filePath = parser.getOptionValue(fileOpt);
			String arg = parser.getOptionValue(argOpt);
			
			FileUtil.ARMOR armor = FileUtil.ARMOR.valueOf(parser.getOptionValue(encodingOpt, FileUtil.ARMOR.none.toString()));
			
			if(filePath != null) {
				// process file
				byte [] sb = FileUtil.readFile(filePath,armor);
				TresBiEntropy bi = new TresBiEntropy(sb);
				Result res = bi.calc();
				System.out.println(res.toJSON());
			}else if(arg != null){
				// process arg
				if(arg.length() ==1){
					com.cryptoregistry.util.entropy.BiEntropy bi = new com.cryptoregistry.util.entropy.BiEntropy(arg.getBytes()[0]);
					com.cryptoregistry.util.entropy.BiEntropy.Result res = bi.calc();
					System.out.println(res.toJSON());
					return;
				}
				
				byte [] bytes = null;
				switch(armor){
					case hex:
					case base16: bytes = Hex.decode(arg.getBytes()); break;
					case base64: bytes = Base64.decode(arg); break;
					case base64url: bytes = Base64.decode(arg, Base64.URL_SAFE); break;
					case none: bytes = arg.getBytes("UTF-8");break;
				}
					TresBiEntropy bi = new TresBiEntropy(bytes);
					Result res = bi.calc();
					System.out.println(res.toJSON());
				
			}else{
				ShowHelpUtil.showHelp("/bientropy-help-message.txt");
			}
		} catch (OptionException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
	
	

}
