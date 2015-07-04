/*
 *  This file is part of Buttermilk
 *  Copyright 2011-2015 David R. Smith All Rights Reserved.
 *
 */
package com.cryptoregistry.app;

import javax.swing.JPanel;
import javax.swing.GroupLayout;
import javax.swing.GroupLayout.Alignment;
import javax.swing.JLabel;
import javax.swing.JTextField;
import javax.swing.LayoutStyle.ComponentPlacement;
import javax.swing.JButton;
import javax.swing.SwingWorker;

import java.awt.Color;
import java.awt.event.ActionListener;
import java.awt.event.ActionEvent;
import java.awt.event.KeyEvent;
import java.awt.event.KeyListener;
import java.util.concurrent.ExecutionException;

import asia.redact.bracket.properties.Properties;

import com.cryptoregistry.handle.CryptoHandle;
import com.cryptoregistry.handle.DomainNameHandle;
import com.cryptoregistry.handle.Handle;

public class RegHandlePanel extends JPanel {

	private static final long serialVersionUID = 1L;
	private final JTextField regHandleTextField;
	private final RegHandleChecker checker;
	
	private final ExceptionHolder exception;
	
	public RegHandlePanel(Properties props){
		super();
		exception = new ExceptionHolder();
		checker = new RegHandleChecker(props);
	
		JLabel lblRegistrationHandle = new JLabel("Registration Handle");
		final JLabel validationLabel = new JLabel("...");
		final JLabel lblAvailable = new JLabel("...");
		
		regHandleTextField = new JTextField("");
		regHandleTextField.setColumns(10);
		
		JButton btnCheckAvailability = new JButton("Check Availability");
		btnCheckAvailability.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				final String regHandle = regHandleTextField.getText();
				if(regHandle == null || regHandle.trim().equals("")){
					// do nothing
					return;
				}
				
				lblAvailable.setText("Checking...");
				lblAvailable.setEnabled(false);
				
				SwingWorker<Boolean,String> worker = new SwingWorker<Boolean,String>() {
					
					@Override
					protected Boolean doInBackground() throws Exception {
						try {
						return checker.check(regHandle);
						}catch(RuntimeException x){
							exception.ex = x;
							return false;
						}
					}
					
					 @Override
					public void done() {
						 try {
							 lblAvailable.setEnabled(true);
								if(get()) {
									lblAvailable.setText("Available!");
								}else{
									if(exception.hasException()){
										lblAvailable.setText(exception.ex.getMessage());
										exception.ex.printStackTrace();
									}else{
										lblAvailable.setText("Not Available, Sorry.");
									}
								}
						} catch (InterruptedException | ExecutionException e) {
							e.printStackTrace();
						}
					}
				};
				worker.execute();
			}
		});
		
		
		regHandleTextField.addKeyListener(new KeyListener() {

			@Override
			public void keyTyped(KeyEvent e) {
				lblAvailable.setText("...");
				String text = regHandleTextField.getText();
				Handle h = CryptoHandle.parseHandle(text);
				if(h.validate()){
					validationLabel.setText("Valid Syntax: type "+h.getClass().getSimpleName());
					validationLabel.setForeground(Color.BLACK);
				}else{
					validationLabel.setText("Formatting error.");
					validationLabel.setForeground(Color.RED);
				}
				
			}

			@Override
			public void keyPressed(KeyEvent e) {
				// keyTyped(e);
			}

			@Override
			public void keyReleased(KeyEvent e) {
				//do nothing
				
			}
			
		});
		
		JButton btnCreate = new JButton("OK");
		btnCreate.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				String handleText = regHandleTextField.getText().trim();
				SwingRegistrationWizardGUI.km.setRegHandle(handleText);
				
				Handle h = CryptoHandle.parseHandle(handleText);
				if(h.validate()){
					if(h instanceof DomainNameHandle){
						// deactivate personal and business contact tabs, activate web contact
						SwingRegistrationWizardGUI.tabbedPane.setEnabledAt(4, false);
						SwingRegistrationWizardGUI.tabbedPane.setEnabledAt(5, false);
						SwingRegistrationWizardGUI.tabbedPane.setEnabledAt(6, true);
					}else{
						// activate personal and business contact tabs, deactivate web contact
						
						SwingRegistrationWizardGUI.tabbedPane.setEnabledAt(4, true);
						SwingRegistrationWizardGUI.tabbedPane.setEnabledAt(5, true);
						SwingRegistrationWizardGUI.tabbedPane.setEnabledAt(6, false);
						SwingRegistrationWizardGUI.tabbedPane.setSelectedIndex(3);
					}
					
					SwingRegistrationWizardGUI.tabbedPane.setSelectedIndex(3);
				}else{
					
				}
			} 
		});
		
		GroupLayout groupLayout = new GroupLayout(this);
		groupLayout.setHorizontalGroup(
			groupLayout.createParallelGroup(Alignment.LEADING)
				.addGroup(groupLayout.createSequentialGroup()
					.addContainerGap()
					.addGroup(groupLayout.createParallelGroup(Alignment.TRAILING)
						.addGroup(groupLayout.createSequentialGroup()
							.addComponent(lblRegistrationHandle)
							.addContainerGap(346, Short.MAX_VALUE))
						.addGroup(groupLayout.createSequentialGroup()
							.addGroup(groupLayout.createParallelGroup(Alignment.LEADING)
								.addComponent(regHandleTextField, GroupLayout.DEFAULT_SIZE, 414, Short.MAX_VALUE)
								.addGroup(groupLayout.createSequentialGroup()
									.addGroup(groupLayout.createParallelGroup(Alignment.TRAILING)
										.addGroup(groupLayout.createSequentialGroup()
											.addGap(10)
											.addComponent(validationLabel)
											.addGap(144)
											.addComponent(lblAvailable)
											.addPreferredGap(ComponentPlacement.RELATED, 124, Short.MAX_VALUE))
										.addGroup(groupLayout.createSequentialGroup()
											.addComponent(btnCheckAvailability)
											.addGap(31)))
									.addGap(47)))
							.addGap(26))
						.addGroup(groupLayout.createSequentialGroup()
							.addComponent(btnCreate)
							.addContainerGap())))
		);
		groupLayout.setVerticalGroup(
			groupLayout.createParallelGroup(Alignment.LEADING)
				.addGroup(groupLayout.createSequentialGroup()
					.addContainerGap()
					.addComponent(lblRegistrationHandle)
					.addGap(10)
					.addComponent(regHandleTextField, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE)
					.addGroup(groupLayout.createParallelGroup(Alignment.LEADING)
						.addGroup(groupLayout.createSequentialGroup()
							.addPreferredGap(ComponentPlacement.RELATED)
							.addGroup(groupLayout.createParallelGroup(Alignment.BASELINE)
								.addComponent(lblAvailable)
								.addComponent(validationLabel)))
						.addGroup(groupLayout.createSequentialGroup()
							.addGap(26)
							.addComponent(btnCheckAvailability)))
					.addPreferredGap(ComponentPlacement.RELATED, 162, Short.MAX_VALUE)
					.addComponent(btnCreate)
					.addContainerGap())
		);
		setLayout(groupLayout);
	}


	public JTextField getRegHandleTextField() {
		return regHandleTextField;
	}
	
	private static class ExceptionHolder{
		
		public Exception ex;

		public ExceptionHolder() {}
		
		public boolean hasException() {
			return ex != null;
		}
	}
}
