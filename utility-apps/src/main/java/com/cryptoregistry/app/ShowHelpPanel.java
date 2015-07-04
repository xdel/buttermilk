/*
 *  This file is part of Buttermilk
 *  Copyright 2011-2015 David R. Smith All Rights Reserved.
 *
 */
package com.cryptoregistry.app;

//import javax.swing.BorderFactory;
import javax.swing.JPanel;
import javax.swing.JTextPane;

import java.awt.Color;
import java.awt.Desktop;
import java.awt.GridLayout;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;

import javax.swing.JScrollPane;
import javax.swing.event.HyperlinkEvent;
import javax.swing.event.HyperlinkListener;

import org.apache.http.client.utils.URIBuilder;

import asia.redact.bracket.properties.Properties;

public class ShowHelpPanel extends JPanel {
	
	final Properties props;
	
	private static final long serialVersionUID = 1L;

	public ShowHelpPanel(Properties _props) {
		super();
		this.props = _props;
		setLayout(new GridLayout(1, 0, 0, 0));
		setBackground(new Color(208, 228, 254));
	//	this.setBorder(BorderFactory.createLineBorder(new Color(208, 228, 254)));
		
		java.net.URL helpURL = this.getClass().getResource("/helptext.html");
		
		final JTextPane textPane = new JTextPane();
		textPane.setBackground(new Color(208, 228, 254));
		textPane.setEditable(false);
		JScrollPane scrollPane = new JScrollPane(textPane);
		scrollPane.setBackground(new Color(208, 228, 254));
		add(scrollPane);
		
		textPane.addHyperlinkListener(new HyperlinkListener() {
	        public void hyperlinkUpdate(final HyperlinkEvent pE) {
	            if (HyperlinkEvent.EventType.ACTIVATED == pE.getEventType()) {
	                String desc = pE.getDescription();
	                if (desc == null || !desc.startsWith("#")) {
	                	try {
							open(url(props));
						} catch (URISyntaxException e) {
							e.printStackTrace();
						}
	                }else{
	                	desc = desc.substring(1);
	                	textPane.scrollToReference(desc);
	                }
	            }
	        }
	    });
		
		try {
			textPane.setPage(helpURL);
		} catch (IOException e) {
			e.printStackTrace();
		}
	}


	private URI url(Properties props) throws URISyntaxException {
		URIBuilder builder = new URIBuilder();
		 builder.setScheme(props.get("registration.direct.scheme"))
	        .setHost(props.get("registration.direct.hostname"))
	        .setPath(props.get("registration.direct.path"))
	        .setPort(props.intValue("registration.direct.port"));
		return builder.build();
	}

	private void open(URI uri) {
	    if (Desktop.isDesktopSupported()) {
	      try {
	        Desktop.getDesktop().browse(uri);
	      } catch (IOException e) { }
	    } else { throw new RuntimeException("No Desktop available to launch browser"); }
	}
	
}
