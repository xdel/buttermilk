/*
 *  This file is part of Buttermilk
 *  Copyright 2011-2014 David R. Smith All Rights Reserved.
 *
 */
package com.cryptoregistry.client.console;

import java.io.File;
import java.util.ArrayList;
import java.util.Date;
import java.util.Iterator;
import java.util.List;

import org.jgroups.util.UUID;

import com.cryptoregistry.client.storage.DataStore;
import com.cryptoregistry.client.storage.Handle;
import com.cryptoregistry.client.storage.Metadata;
import com.cryptoregistry.rsa.CryptoFactory;
import com.cryptoregistry.rsa.RSAKeyContents;
import com.cryptoregistry.rsa.RSAKeyMetadata;
import com.cryptoregistry.util.CmdLineParser;
import com.cryptoregistry.util.CmdLineParser.OptionException;
import com.cryptoregistry.util.ShowHelpUtil;
import com.cryptoregistry.util.CmdLineParser.Option;

public class ButtermilkExec {
	
	private DataStore ds;
	
	private CmdLineParser parser;
	
	private Option<Boolean> shutdownOpt, genKeyOpt, statusOpt, listOpt, importOpt, exportOpt,
	signatureOpt, listKeyGenAlgsOpt, listCurveNamesOpt, listNamedParametersOpt, 
	showCustomCurveExampleOpt, showCustomParamExampleOpt, infoOpt;
	
	private Option<String> regHandleOpt, fileOpt, charsetOpt,
	keyOpt, contactOpt, dataOpt, algorithmOpt, handleOpt,
	curveNameOpt, namedParamsOpt;
	
	private Option<Integer> certaintyOpt, publicExponentOpt, strengthOpt;
	
	String commandLine;
	
	public ButtermilkExec(DataStore ds){
		this.ds = ds;
	}
	
	public void init(String [] args){
		
		System.err.println("in init()");
		
		//stash it
		 StringBuilder b = new StringBuilder();
		 for(String s: args){
			 b.append(s);
			 b.append(" ");
		 }
		 b.deleteCharAt(b.length()-1);
		 commandLine = b.toString();
		 
		 parser = new CmdLineParser();
		 shutdownOpt = parser.addBooleanOption('s', "shutdown");
		 genKeyOpt = parser.addBooleanOption('g', "genkey");
		 regHandleOpt = parser.addStringOption('r', "regHandle");
		 fileOpt = parser.addStringOption('f', "file");
		 charsetOpt = parser.addStringOption('c', "charset");
		 statusOpt = parser.addBooleanOption("status");
		 listOpt = parser.addBooleanOption('l', "list");
		 importOpt = parser.addBooleanOption('i', "import");
		 exportOpt = parser.addBooleanOption('e', "export");
		 keyOpt = parser.addStringOption('k', "key");
		 contactOpt = parser.addStringOption("contact");
		 dataOpt = parser.addStringOption("data");
		 signatureOpt = parser.addBooleanOption("signature");
		 algorithmOpt = parser.addStringOption('a', "algorithm");
		 handleOpt = parser.addStringOption('h', "handle");
		 listKeyGenAlgsOpt = parser.addBooleanOption("listKeyGenAlgs");
		 listCurveNamesOpt = parser.addBooleanOption("listCurveNames");
		 listNamedParametersOpt = parser.addBooleanOption("listNamedParameters");
		 showCustomCurveExampleOpt = parser.addBooleanOption("showCustomCurveExample");
		 showCustomParamExampleOpt = parser.addBooleanOption("showCustomParamExample");
		 infoOpt = parser.addBooleanOption("info");
		
		// rsa
		 certaintyOpt = parser.addIntegerOption("certainty");
		 publicExponentOpt = parser.addIntegerOption("publicExponent");
		 strengthOpt = parser.addIntegerOption("strength");
		
		// EC
		 curveNameOpt = parser.addStringOption("curveNameAlgs");
		
		// NTRU
		 namedParamsOpt = parser.addStringOption("namedParams");
		
		try {
			parser.parse(args);
			System.err.println("parsed args");
		} catch (OptionException e) {
			e.printStackTrace();
		}
	}
	
	/**
	 * Traps exceptions
	 * 
	 * @return
	 */
	public String execute(){
		 
		System.err.println("in execute()");
		
		String output = null;
		
		Date start = new Date();
		try {
			output = _execute();
		}catch(Exception x){
			StackTraceElement [] stes = x.getStackTrace();
			StringBuffer buf = new StringBuffer();
			buf.append("\n");
			buf.append(x.getMessage());
			for(StackTraceElement e : stes){
				buf.append(e.toString());
				buf.append("\n");
			}
			output = buf.toString();
		}
		Date end = new Date();
		long duration = end.getTime()-start.getTime();
		return ShowHelpUtil.formatResponse(commandLine, output, duration);
		
	}

	private String _execute() {
		
		String cmd = null;
		
		// verbs
		 if(parser.getOptionValue(genKeyOpt, false)) cmd = "KEYGEN";
		 else if(parser.getOptionValue(shutdownOpt, false)) cmd = "SHUTDOWN";
		 else if(parser.getOptionValue(statusOpt, false)) cmd = "STATUS";
		 else if(parser.getOptionValue(listOpt, false)) cmd = "LIST";
		 else if(parser.getOptionValue(infoOpt, false)) cmd = "INFO";
		 else if(parser.getOptionValue(importOpt, false)) cmd = "IMPORT";
		 else if(parser.getOptionValue(exportOpt, false)) cmd = "EXPORT";
		 else if(parser.getOptionValue(signatureOpt, false)) cmd = "SIG";
		 else if(parser.getOptionValue(listKeyGenAlgsOpt, false)) cmd = "LISTALGS";
		 else if(parser.getOptionValue(listCurveNamesOpt, false)) cmd = "LISTCURVES";
		 else if(parser.getOptionValue(listNamedParametersOpt, false)) cmd = "LISTNAMEDPARAMS";
		 else if(parser.getOptionValue(showCustomCurveExampleOpt, false)) cmd = "SHOWCUSTOMCURVEEXAMPLE";
		 else if(parser.getOptionValue(showCustomParamExampleOpt, false)) cmd = "SHOWCUSTOMPARAMEXAMPLE";
		 
		 if(cmd == null) {
			return message(); 
		 }
		 
		 System.err.println("command: "+cmd);
		 
		 switch(cmd) {
		 	case "SHUTDOWN": {
		 		return "DONE";
		 	}
		 	case "LIST" : {
		 		String alg = parser.getOptionValue(algorithmOpt, "none");
		 		String regHandle = parser.getOptionValue(regHandleOpt, "none");
		 		
		 		if((!alg.equals("none")) && (!regHandle.equals("none"))){
		 			// both alg and reg handle limits
		 			
		 		}else if(!alg.equals("none")) {
		 			// limit by alg
		 			
		 		}else if(!regHandle.equals("none")) {
		 			// limit by reg handle
		 			
		 		}else{
		 			// all
		 			List<Metadata> items = new ArrayList<Metadata>();
		 			Iterator<Handle> iter = ds.getViews().getMetadataMap().keySet().iterator();
		 			while(iter.hasNext()){
		 				Handle handle = iter.next();
		 				items.add(ds.getViews().getMetadataMap().get(handle));
		 			}
		 			
		 			return showList(items);
		 		}
		 	}
		 	case "KEYGEN": {
		 		String alg = parser.getOptionValue(algorithmOpt, "none");
		 		if(alg.equals("none")){
		 			return "Please use the -a flag and provide an algorithm";
		 		}
		 		
		 		String handle = parser.getOptionValue(handleOpt, UUID.randomUUID().toString());
		 		String regHandle = parser.getOptionValue(regHandleOpt, null);
	 			if(regHandle == null) regHandle = ds.getRegHandle();
		 		
		 		if(alg.equals("RSA")){
		 			Integer certainty = parser.getOptionValue(certaintyOpt, 100);
		 			Integer publicExponent = parser.getOptionValue(publicExponentOpt, 65537);
		 			Integer strength = parser.getOptionValue(strengthOpt, 2048);
		 			
		 			System.err.println("Values for RSA genkey: "+certainty+", "+publicExponent+", "+strength);
		 			
		 			if(certainty < 10) {
		 				throw new RuntimeException("RSA Primality certainty test count looks too low.");
		 			}
		 			
		 			if((strength % 1024) != 0) {
		 				throw new RuntimeException("RSA key size must be a multiple of 1024");
		 			}
		 			
		 			return genRSAKey(regHandle,handle,certainty,publicExponent,strength);
		 		}
		 	}
		 	default: throw new RuntimeException("Unknown Verb: "+cmd);
		 }
		 
		// return "OK";

	}
	
	public void shutdownServer() {
		
	}
	
	public String genRSAKey(String regHandle, String handle, int certainty,int publicExponent,int strength){
		RSAKeyMetadata meta = RSAKeyMetadata.createDefault(handle);
		RSAKeyContents contents = CryptoFactory.INSTANCE.generateKeys(meta,publicExponent,strength,certainty);
		ds.getViews().put(regHandle, contents);
		return handle;
	}
	
	public String showList(List<Metadata> metaList){
		StringBuffer buf = new StringBuffer();
		Iterator<Metadata> iter = metaList.iterator();
		while(iter.hasNext()){
			Metadata meta = iter.next();
			buf.append(meta);
			buf.append("\n");
		}
		return buf.toString();
	}

	
	public String message() {
		return ShowHelpUtil.help("/help-message.txt");
	}

}
