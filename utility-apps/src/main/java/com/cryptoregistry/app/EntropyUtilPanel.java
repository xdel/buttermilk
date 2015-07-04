/*
 *  This file is part of Buttermilk
 *  Copyright 2011-2015 David R. Smith All Rights Reserved.
 *
 */
package com.cryptoregistry.app;

import java.awt.Color;
import java.awt.Cursor;
import java.awt.Desktop;
import java.awt.event.KeyAdapter;
import java.awt.event.KeyEvent;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.Charset;

import javax.swing.JPanel;
import javax.swing.GroupLayout;
import javax.swing.GroupLayout.Alignment;
import javax.swing.JLabel;
import javax.swing.LayoutStyle.ComponentPlacement;
import javax.swing.JTextArea;

import com.cryptoregistry.util.entropy.TresBiEntropy;
import com.cryptoregistry.util.entropy.TresBiEntropy.Result;

public class EntropyUtilPanel extends JPanel {

	private static final long serialVersionUID = 1L;
	
	JLabel lblEntropy;
	JTextArea textArea;

	public EntropyUtilPanel() {
		super();
		setBackground(new Color(208, 228, 254));
		final String url = "http://arxiv.org/ftp/arxiv/papers/1305/1305.0954.pdf";
		JLabel lblFindEntropyOf = new JLabel("<html>Compute the binary entropy of the text using <a href='"+url+"'>Croll's method</a></html>");
		lblFindEntropyOf.setCursor(new Cursor(Cursor.HAND_CURSOR));
		lblFindEntropyOf.addMouseListener(new MouseAdapter() {
	            @Override
	            public void mouseClicked(MouseEvent e) {
	                    try {
	                            Desktop.getDesktop().browse(new URI(url));
	                    } catch (URISyntaxException | IOException ex) {
	                            //It looks like there's a problem
	                    }
	            }
	        });
		
		
		textArea = new JTextArea();
		textArea.addKeyListener(new KeyAdapter() {
			@Override
			public void keyReleased(KeyEvent e) {
				checkEntropy();
			}
		});
		
		lblEntropy = new JLabel("...");
		
		GroupLayout groupLayout = new GroupLayout(this);
		groupLayout.setHorizontalGroup(
			groupLayout.createParallelGroup(Alignment.TRAILING)
				.addGroup(Alignment.LEADING, groupLayout.createSequentialGroup()
					.addContainerGap()
					.addGroup(groupLayout.createParallelGroup(Alignment.LEADING)
						.addComponent(textArea, GroupLayout.DEFAULT_SIZE, 430, Short.MAX_VALUE)
						.addComponent(lblFindEntropyOf, GroupLayout.PREFERRED_SIZE, 392, GroupLayout.PREFERRED_SIZE)
						.addGroup(groupLayout.createSequentialGroup()
							.addGap(40)
							.addComponent(lblEntropy)))
					.addContainerGap())
		);
		groupLayout.setVerticalGroup(
			groupLayout.createParallelGroup(Alignment.LEADING)
				.addGroup(groupLayout.createSequentialGroup()
					.addGap(21)
					.addComponent(lblFindEntropyOf, GroupLayout.PREFERRED_SIZE, 26, GroupLayout.PREFERRED_SIZE)
					.addPreferredGap(ComponentPlacement.RELATED)
					.addComponent(textArea, GroupLayout.PREFERRED_SIZE, 164, GroupLayout.PREFERRED_SIZE)
					.addPreferredGap(ComponentPlacement.UNRELATED)
					.addComponent(lblEntropy)
					.addContainerGap(58, Short.MAX_VALUE))
		);
		setLayout(groupLayout);
	}
	
	private void checkEntropy() {
		
		byte [] b0 = textArea.getText().trim().getBytes(Charset.forName("UTF-8"));
		
		if(b0 == null || b0.length ==0) {
			this.lblEntropy.setText("Entropy: 0 bits");
			return;
		}
		
		TresBiEntropy bi = new TresBiEntropy(b0);
		Result res = bi.calc();
		int entropy = (int) res.bitsOfEntropy;
		this.lblEntropy.setText("Entropy: "+entropy+" bits");
	}
	

}
