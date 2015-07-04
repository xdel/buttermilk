/*
 *  This file is part of Buttermilk
 *  Copyright 2011-2015 David R. Smith All Rights Reserved.
 *
 */
package com.cryptoregistry.app;

import java.awt.Cursor;
import java.awt.Dimension;
import java.awt.Font;
import java.awt.Toolkit;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.awt.image.BufferedImage;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringWriter;

import javax.imageio.ImageIO;
import javax.swing.ImageIcon;
import javax.swing.JFrame;
import javax.swing.JLabel;

import asia.redact.bracket.properties.Properties;

public class AboutFrame extends JFrame {

	Properties props;
	private static final long serialVersionUID = 1L;

	public AboutFrame(Properties props) {
		super();
		this.props = props;
		this.setUndecorated(true);
		this.setDefaultCloseOperation(DISPOSE_ON_CLOSE);
		BufferedImage image = null;

	    Dimension screenSize = Toolkit.getDefaultToolkit().getScreenSize(); //this is your screen size
	    try {
			image = ImageIO.read(this.getClass().getResourceAsStream("/hand400-trans.png"));
		} catch (IOException e) {
			e.printStackTrace();
		}
	    
	    final AboutFrame af = this;
	    StringWriter writer = new StringWriter();
	    writer.append("<html>");
	    writer.append("<p align='center'>Version: ");
	    writer.append(props.get("app.version"));
	    writer.append("</p><html>");
	    JLabel picLabel = new JLabel(writer.toString(), new ImageIcon(image), JLabel.CENTER);
	    picLabel.setFont(new Font("Verdana", Font.PLAIN, 32));
	    picLabel.setCursor(new Cursor(Cursor.HAND_CURSOR));
	    picLabel.addMouseListener(new MouseAdapter() {
	    	public void mouseClicked(MouseEvent e) {
	    		  af.setVisible(false);
	    	      af.dispose();
	    	}
	    });
	    
	    
	    getContentPane().add(picLabel); //puts label inside the jframe
	    setSize(image.getWidth(), image.getHeight()); //gets h and w of image and sets jframe to the size
	    int x = (screenSize.width - getSize().width)/2; //These two lines are the dimensions
	    int y = (screenSize.height - getSize().height)/2;//of the center of the screen
	    setLocation(x, y); //sets the location of the jframe
	    pack();
	    setVisible(true); //makes the jframe visible
	}
	
	public static void main(String [] str){
		 javax.swing.SwingUtilities.invokeLater(new Runnable() {
	            public void run() {
	            	InputStream in = Thread.currentThread()
	            				.getContextClassLoader().getResourceAsStream("regwizard.properties");
	            		Properties props = Properties.Factory.getInstance(in);
	            		new AboutFrame(props);
	            }
	     });
	}

}
