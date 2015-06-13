/*
 *  This file is part of Buttermilk
 *  Copyright 2011-2015 David R. Smith All Rights Reserved.
 *
 */
package com.cryptoregistry.app;

import java.awt.Color;
import java.awt.GridLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.beans.PropertyChangeEvent;
import java.beans.PropertyChangeListener;

import javax.swing.BorderFactory;
import javax.swing.BoxLayout;
import javax.swing.ImageIcon;
import javax.swing.JButton;
import javax.swing.JPanel;
import javax.swing.JLabel;

public class ChecklistPanel extends JPanel implements PropertyChangeListener {

	private static final long serialVersionUID = 1L;
	
	JLabel lblKMPath, lblRegHandleSelected, lblPasswordSet, lblSecureKey, lblKeyForPublication;
	
	JLabel lblContactSet, lblSignatureCompleted, lblRegistrationSent;
	
	KM km;
	
	JButton btnRegister;
	
	public ChecklistPanel(KM km) {
		this();
		this.km = km;
		km.addPropertyChangeListener(this);
		setBackground(new Color(208, 228, 254));
	}
	

	public ChecklistPanel() {
		
		this.setBorder(BorderFactory.createEmptyBorder(20, 20, 20, 20));
		this.setLayout(new GridLayout(2,0,0,0));
		
		JPanel panel = new JPanel();
		panel.setBackground(new Color(208, 228, 254));
		panel.setBorder(BorderFactory.createEmptyBorder(20, 20, 20, 20));
		
		panel.setLayout(new BoxLayout(panel, BoxLayout.PAGE_AXIS));
		
		lblKMPath = new JLabel("Key Materials Directory Set", createImageIcon("/checkbox_empty.png", ""), JLabel.CENTER);
		panel.add(lblKMPath);
		
		lblRegHandleSelected = new JLabel("Registration Handle Chosen", createImageIcon("/checkbox_empty.png", ""), JLabel.CENTER);
		panel.add(lblRegHandleSelected);
		
		lblPasswordSet = new JLabel("Password For Secure Key Chosen", createImageIcon("/checkbox_empty.png", ""), JLabel.CENTER);
		panel.add(lblPasswordSet);
		
		lblSecureKey = new JLabel("Secure Key Created", createImageIcon("/checkbox_empty.png", ""), JLabel.CENTER);
		panel.add(lblSecureKey);
		
		lblKeyForPublication = new JLabel("Key For Publication Created", createImageIcon("/checkbox_empty.png", ""), JLabel.CENTER);
		panel.add(lblKeyForPublication);
		
		lblContactSet = new JLabel("Contact Info created", createImageIcon("/checkbox_empty.png", ""), JLabel.CENTER);
		panel.add(lblContactSet);
		
		lblSignatureCompleted = new JLabel("Signature Created", createImageIcon("/checkbox_empty.png", ""), JLabel.CENTER);
		panel.add(lblSignatureCompleted);
		
		lblRegistrationSent = new JLabel("Registration Sent", createImageIcon("/checkbox_empty.png", ""), JLabel.CENTER);
		panel.add(lblRegistrationSent);
		
		add(panel);
		
		JPanel panel1 = new JPanel();
		panel1.setBackground(new Color(208, 228, 254));
		panel1.setBorder(BorderFactory.createEmptyBorder(20, 20, 20, 20));
		btnRegister = new JButton("Send Registration Request");
		btnRegister.setEnabled(false);
		btnRegister.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				// do registration!
			}
		});
		panel1.add(btnRegister);
		
		add(panel1);
		
	}
	
	protected ImageIcon createImageIcon(String path, String description) {
			java.net.URL imgURL = getClass().getResource(path);
			if (imgURL != null) {
				ImageIcon icon =  new ImageIcon(imgURL, description);
				System.err.println(icon);
				return icon;
			} else {
				System.err.println("Couldn't find file: " + path);
				return null;
			}
	}

	@Override
	public void propertyChange(PropertyChangeEvent evt) {
		final String prop = evt.getPropertyName();
		switch(prop){
			case "kmPath" : {
				this.lblKMPath.setIcon(createImageIcon("/checkbox_full.png", ""));
				break;
			}
			case "regHandle":{
				this.lblRegHandleSelected.setIcon(createImageIcon("/checkbox_full.png", ""));
				break;
			}
			case "password": {
				this.lblPasswordSet.setIcon(createImageIcon("/checkbox_full.png", ""));
				break;
			}
			case "keyAlg":{
				
				break;
			}
			case "pbeAlg": {
				
				break;
			}
			case "secureKey": {
				this.lblSecureKey.setIcon(createImageIcon("/checkbox_full.png", ""));
				break;
			}
			case "keyForPublication": {
				this.lblKeyForPublication.setIcon(createImageIcon("/checkbox_full.png", ""));
				break;
			}
			case "contacts": {
				this.lblContactSet.setIcon(createImageIcon("/checkbox_full.png", ""));
				break;
			}
			case "signature": {
				this.lblSignatureCompleted.setIcon(createImageIcon("/checkbox_full.png", ""));
				this.btnRegister.setEnabled(true);
				break;
			}
			case "formatter": {
				
				break;
			}
		}
	}

	public JButton getBtnRegister() {
		return btnRegister;
	}

}
