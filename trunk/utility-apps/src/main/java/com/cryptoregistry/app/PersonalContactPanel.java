/*
 *  This file is part of Buttermilk
 *  Copyright 2011-2015 David R. Smith All Rights Reserved.
 *
 */
package com.cryptoregistry.app;
import javax.swing.JPanel;
import javax.swing.GroupLayout;
import javax.swing.SwingWorker;
import javax.swing.GroupLayout.Alignment;
import javax.swing.JLabel;
import javax.swing.JTextField;
import javax.swing.LayoutStyle.ComponentPlacement;
import javax.swing.JButton;

import java.awt.event.ActionListener;
import java.awt.event.ActionEvent;
import java.util.concurrent.ExecutionException;

import com.cryptoregistry.CryptoContact;

public class PersonalContactPanel extends JPanel {

	private static final long serialVersionUID = 1L;
	private JTextField countryTextField;
	private JTextField emailTextField;
	private JTextField givenNameTextField;
	private JTextField familyNameTextField;
	private JTextField mobilePhoneTextField;
	
	private CryptoContact contact;

	public PersonalContactPanel() {
		super();
		
		JLabel lblCountry = new JLabel("Country");
		
		JLabel lblEmail = new JLabel("Email.0");
		
		countryTextField = new JTextField();
		countryTextField.setColumns(10);
		
		emailTextField = new JTextField();
		emailTextField.setColumns(10);
		
		final JButton btnCreateContact = new JButton("Create Contact");
		btnCreateContact.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				btnCreateContact.setText("Working...");
				btnCreateContact.setEnabled(false);
				SwingWorker<Void,String> worker = new SwingWorker<Void,String>() {
					protected Void doInBackground() throws Exception {
						createContactRecord();
						return null;
					}
					 @Override
					public void done() {
					  try {
							get();
							if(contact != null)
								SwingRegistrationWizardGUI.km.addContact(contact);
							 
						  } catch (InterruptedException | ExecutionException e) {
							e.printStackTrace();
						  }
						 
						 btnCreateContact.setText("Create Contact");
						 btnCreateContact.setEnabled(true);
						 SwingRegistrationWizardGUI.tabbedPane.setSelectedIndex(7);
					}
				};
				worker.execute();
				
			}
		});
		
		JLabel lblGivenname = new JLabel("GivenName.0");
		
		givenNameTextField = new JTextField();
		givenNameTextField.setColumns(10);
		
		JLabel lblFamilyname = new JLabel("FamilyName.0");
		
		familyNameTextField = new JTextField();
		familyNameTextField.setColumns(10);
		
		JLabel lblMobile = new JLabel("MobilePhone.0");
		
		mobilePhoneTextField = new JTextField();
		mobilePhoneTextField.setColumns(10);
		
		GroupLayout groupLayout = new GroupLayout(this);
		groupLayout.setHorizontalGroup(
			groupLayout.createParallelGroup(Alignment.LEADING)
				.addGroup(groupLayout.createSequentialGroup()
					.addGap(19)
					.addGroup(groupLayout.createParallelGroup(Alignment.LEADING)
						.addGroup(Alignment.TRAILING, groupLayout.createSequentialGroup()
							.addComponent(btnCreateContact)
							.addGap(14))
						.addGroup(groupLayout.createSequentialGroup()
							.addGroup(groupLayout.createParallelGroup(Alignment.LEADING)
								.addComponent(lblCountry)
								.addComponent(lblEmail)
								.addComponent(lblGivenname)
								.addComponent(lblFamilyname)
								.addComponent(lblMobile))
							.addGap(23)
							.addGroup(groupLayout.createParallelGroup(Alignment.LEADING)
								.addComponent(emailTextField, GroupLayout.PREFERRED_SIZE, 258, GroupLayout.PREFERRED_SIZE)
								.addGroup(groupLayout.createParallelGroup(Alignment.TRAILING, false)
									.addComponent(familyNameTextField, Alignment.LEADING)
									.addComponent(givenNameTextField, Alignment.LEADING)
									.addComponent(countryTextField, Alignment.LEADING, GroupLayout.DEFAULT_SIZE, 170, Short.MAX_VALUE))
								.addComponent(mobilePhoneTextField, GroupLayout.PREFERRED_SIZE, 168, GroupLayout.PREFERRED_SIZE))
							.addContainerGap(80, Short.MAX_VALUE))))
		);
		groupLayout.setVerticalGroup(
			groupLayout.createParallelGroup(Alignment.TRAILING)
				.addGroup(groupLayout.createSequentialGroup()
					.addContainerGap()
					.addGroup(groupLayout.createParallelGroup(Alignment.LEADING)
						.addComponent(lblGivenname)
						.addComponent(givenNameTextField, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE))
					.addPreferredGap(ComponentPlacement.RELATED)
					.addGroup(groupLayout.createParallelGroup(Alignment.BASELINE)
						.addComponent(lblFamilyname)
						.addComponent(familyNameTextField, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE))
					.addGap(29)
					.addGroup(groupLayout.createParallelGroup(Alignment.BASELINE)
						.addComponent(lblCountry)
						.addComponent(countryTextField, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE))
					.addPreferredGap(ComponentPlacement.RELATED)
					.addGroup(groupLayout.createParallelGroup(Alignment.BASELINE)
						.addComponent(emailTextField, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE)
						.addComponent(lblEmail))
					.addPreferredGap(ComponentPlacement.RELATED)
					.addGroup(groupLayout.createParallelGroup(Alignment.BASELINE)
						.addComponent(lblMobile)
						.addComponent(mobilePhoneTextField, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE))
					.addPreferredGap(ComponentPlacement.RELATED, 172, Short.MAX_VALUE)
					.addComponent(btnCreateContact)
					.addContainerGap())
		);
		setLayout(groupLayout);
		
	}

	public JTextField getTextField() {
		return givenNameTextField;
	}
	
	private void createContactRecord() {
		
		CryptoContact contact = new CryptoContact();
		
			contact.add("contactType", "Person");
			contact.add("GivenName.0", this.givenNameTextField.getText());
			contact.add("FamilyName.0", this.familyNameTextField.getText());
			contact.add("Email.0", this.emailTextField.getText());
			contact.add("MobilePhone.0", this.mobilePhoneTextField.getText());
			contact.add("Country", this.countryTextField.getText());
			this.contact = contact;
	}
}
