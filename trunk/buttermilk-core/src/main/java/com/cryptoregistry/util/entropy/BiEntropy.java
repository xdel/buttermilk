/*
 *  This file is part of Buttermilk(TM) 
 *  Copyright 2013-2014 David R. Smith for cryptoregistry.com
 *
 */
package com.cryptoregistry.util.entropy;

import java.io.IOException;
import java.io.StringWriter;
import java.text.DecimalFormat;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.Map;

import com.cryptoregistry.util.FileUtil;
import com.fasterxml.jackson.core.JsonGenerationException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;

/**
 * Implementation of bientropy algorithm as described in
 * 
 * http://arxiv.org/ftp/arxiv/papers/1305/1305.0954.pdf
 * 
 * This class is really useful only for one byte inputs which is probably not
 * what brought you looking for this code. See TresBiEntropy class for 
 * arbitrary length inputs such as can be used with a password or key
 * 
 * @author Dave
 * @TresBiEntropy
 */
public class BiEntropy {

	private byte input;
	private ArrayList<Character> binaryExpansion;
	
	final static Character ZERO = new Character('0');
	final static Character ONE = new Character('1');
	final DecimalFormat format = new DecimalFormat("#######0.000");
	
	String bitsAsString;
	
	double U, T; // intermediate values
	
	public BiEntropy(byte input) {
		this.input = input;
		binaryExpansion = new ArrayList<Character>();
	}
	
	/**
	 * Convert the byte from a 2's complement (signed byte) value into an unsigned integer value
	 */
	private void collect(){
		int b = ((int) input) & 0xFF; 
		push(b);
	}
	
	/**
	 * Convert byte into a char array of ones and zeroes characters, push 
	 * on to the binaryExpansion stack
	 * 
	 * @param b
	 */
	private void push(int b){
		char [] word = bitsAsString(b).toCharArray();
		for(char ch : word){
			binaryExpansion.add(ch);
		}
	}
	
	/**
	 * Compute bientropy for the primary binary expansion and then recurse to do
	 * the derivatives.
	 * 
	 * @param list
	 */
	private void compute(ArrayList<Character> list) {
		
		double k = 0;
		double l = list.size();
		for(int i = 0; i<list.size();i++){
			if(list.get(i).equals(ONE)){
				k++;
			}
		}
		
		double p = k/l;
		double p1 = 1-p;
		double p2 = p == 0 ? 0 : (-p * (Math.log(p)/Math.log(2)));
		double q = p1 == 0 ? 0 : (-p1 * (Math.log(p1)/Math.log(2)));
		double bien = p2+q;
	
		double r = binaryExpansion.size() - (list.size() - 1);
		double r1 = Math.pow(2, r-1);
		double u = bien*r1;
		
		T+=r1;
		U+=u;
		
	//	System.err.println("binaryExpansion="+list+", BiEn="+format.format(bien)+", k="+r+", (r-1)^2="+r1+", bien*(r-1)^2="+format.format(u));
			
		// don't do a list of 1 item or less - escape recurse
		if( list.size() == 2) return;
		
		// build the derivative binary expansion
		ArrayList<Character> derivative = new ArrayList<Character>();
		for(int i = 0; i<list.size()-1;i++){
			Character c0 = list.get(i);
			Character c1 = list.get(i+1);
			if(c0.equals(c1)) derivative.add(ZERO);
			else derivative.add(ONE);
		}
		
		compute(derivative);
		
	}
	
	
	
	public Result calc() {
		
		// initial state
		U=T=0;
		binaryExpansion.clear();
		
		collect();
		compute(binaryExpansion);
		double res = U/T;
		StringBuffer buf = new StringBuffer();
		for(Character c: binaryExpansion){
			buf.append(c);
			buf.append(" ");
		}
		buf.deleteCharAt(buf.length()-1);
		//bitsAsString = binaryExpansion.toString();
		bitsAsString = buf.toString();
		return new Result(input, bitsAsString, res, res*1*8);
	}
	

	private String bitsAsString(int b) {
		String s = Integer.toBinaryString(b);
		if(s.length() > 8) throw new RuntimeException("Expecting to work with 8 bits or less");
		if(s.length() == 8) return s;
		else if(s.length() == 7) return "0"+s;
		else if(s.length() == 6) return "00"+s;
		else if(s.length() == 5) return "000"+s;
		else if(s.length() == 4) return "0000"+s;
		else if(s.length() == 3) return "00000"+s;
		else if(s.length() == 2) return "000000"+s;
		else if(s.length() == 1) return "0000000"+s;
		else if(s.length() == 0) return "00000000";
		else return "";
	}
	
//	public static void main(String [] args){
//		BiEntropy bi = new BiEntropy((byte) 'x');
//		Result result = bi.calc();
//		System.err.println(result);
//	}
	
	public class Result {
		
		public FileUtil.ARMOR armor;
		public double biEntropy;
		public double bitsOfEntropy;
		private byte in;
		String bitsAsString;
		
		public Result(byte in, String bitsAsString, double biEntropy, double bitsOfEntropy) {
			super();
			this.biEntropy = biEntropy;
			this.bitsOfEntropy = bitsOfEntropy;
			this.in = in;
			this.bitsAsString = bitsAsString;
			
		}

		@Override
		public String toString() {
			return "Result [biEntropy=" + format.format(biEntropy) + ", bitsOfEntropy="
					+ Math.round(bitsOfEntropy) + "]";
		}
		
		public String biEntropyFormatted(){
			return format.format(biEntropy);
		}
		
		public String toJSON() {
			Map<String,Object> map = new LinkedHashMap<String,Object>();
			map.put("version", "Buttermilk BiEntropy v1.0");
			map.put("algorithm", "BiEntropy");
			map.put("input", Character.valueOf((char)in));
			map.put("bits", bitsAsString);
			map.put("biEntropy", format.format(biEntropy));
			map.put("bitsOfEntropy", Math.round(bitsOfEntropy));
			ObjectMapper mapper = new ObjectMapper();
			mapper.enable(SerializationFeature.INDENT_OUTPUT);
			StringWriter writer = new StringWriter();
			try {
				mapper.writeValue(writer, map);
			} catch (JsonGenerationException e) {
				e.printStackTrace();
			} catch (JsonMappingException e) {
				e.printStackTrace();
			} catch (IOException e) {
				e.printStackTrace();
			}
			return writer.toString();
		}
		
		public String toCSV() {
			StringBuffer buf = new StringBuffer();
			buf.append("version");
			buf.append(",");
			buf.append("algorithm");
			buf.append(",");
			buf.append("input");
			buf.append(",");
			buf.append("bits");
			buf.append(",");
			buf.append("biEntropy");
			buf.append(",");
			buf.append("bitsOfEntropy");
			buf.append("\n");
			
			buf.append( "Buttermilk BiEntropy v1.0");
			buf.append(",");
			buf.append("BiEntropy");
			buf.append(",");
			buf.append(Character.valueOf((char)in));
			buf.append(",");
			buf.append(bitsAsString);
			buf.append(",");
			buf.append(format.format(biEntropy));
			buf.append(",");
			buf.append(Math.round(bitsOfEntropy));
			buf.append("\n");
			
			return buf.toString();
		}
		
		
		@Override
		public int hashCode() {
			final int prime = 31;
			int result = 1;
			result = prime * result + getOuterType().hashCode();
			long temp;
			temp = Double.doubleToLongBits(biEntropy);
			result = prime * result + (int) (temp ^ (temp >>> 32));
			temp = Double.doubleToLongBits(bitsOfEntropy);
			result = prime * result + (int) (temp ^ (temp >>> 32));
			return result;
		}

		@Override
		public boolean equals(Object obj) {
			if (this == obj)
				return true;
			if (obj == null)
				return false;
			if (getClass() != obj.getClass())
				return false;
			Result other = (Result) obj;
			if (!getOuterType().equals(other.getOuterType()))
				return false;
			if (Double.doubleToLongBits(biEntropy) != Double
					.doubleToLongBits(other.biEntropy))
				return false;
			if (Double.doubleToLongBits(bitsOfEntropy) != Double
					.doubleToLongBits(other.bitsOfEntropy))
				return false;
			return true;
		}

		private BiEntropy getOuterType() {
			return BiEntropy.this;
		}
	}

}
