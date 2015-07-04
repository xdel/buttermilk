/*
 *  This file is part of Buttermilk
 *  Copyright 2011-2015 David R. Smith All Rights Reserved.
 *
 */
package com.cryptoregistry.app;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;
import java.io.IOException;

import javax.swing.JFileChooser;
import javax.swing.JPanel;
import javax.swing.GroupLayout;
import javax.swing.GroupLayout.Alignment;
import javax.swing.JLabel;
import javax.swing.JTextField;
import javax.swing.LayoutStyle.ComponentPlacement;
import javax.swing.JButton;

import asia.redact.bracket.properties.Properties;

public class SettingsPanel extends JPanel {

	private static final long serialVersionUID = 1L;
	private JTextField parentFolderTextField;
	
	JFileChooser fc;
	private JTextField privateEmailTextField;

	public SettingsPanel(Properties props) {
		
		String userDir = System.getProperties().getProperty("user.dir");
		File defaultPath = new File(new File(userDir), "km");
		SwingRegistrationWizardGUI.session = new RequestSession(defaultPath);
		 
		String canonical = "";
		
		try {
			canonical = defaultPath.getCanonicalPath();
		} catch (IOException e) {}
		
		JLabel lblKeyMaterialsFolder = new JLabel("Key Materials Folder");
		
		parentFolderTextField = new JTextField(canonical);
		parentFolderTextField.setColumns(10);
		final JPanel _parent = this;
		fc = new JFileChooser();
		fc.setCurrentDirectory(defaultPath);
		fc.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
		
		JButton btnBrowse = new JButton("Browse");
		btnBrowse.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				int returnVal = fc.showOpenDialog(_parent);
				 if (returnVal == JFileChooser.APPROVE_OPTION) {
			            File file = fc.getSelectedFile();
			            try {
			            	String path = file.getCanonicalPath();
							parentFolderTextField.setText(path);
						} catch (IOException e1) {}
			        } else {
			           
			        }
				fc.setVisible(false);
			}
		});
		
		JButton btnOk = new JButton("OK");
		btnOk.addActionListener(new ActionListener() {

			@Override
			public void actionPerformed(ActionEvent e) {
				String path = parentFolderTextField.getText().trim();
				SwingRegistrationWizardGUI.km.setPrivateEmail(privateEmailTextField.getText().trim());
				SwingRegistrationWizardGUI.km.setKmPath(path);
				SwingRegistrationWizardGUI.session = new RequestSession(new File(path));
				SwingRegistrationWizardGUI.tabbedPane.setSelectedIndex(2);
			}
			
		});
		
		JLabel lblPrivateEmail = new JLabel("Private Email");
		
		privateEmailTextField = new JTextField();
		privateEmailTextField.setColumns(10);
		
		JLabel lblThisEmailAddress = new JLabel("<html><i>This email address is used in the registration process only<br>and is not publicly displayed on the web site</i></html>");
		
		GroupLayout groupLayout = new GroupLayout(this);
		groupLayout.setHorizontalGroup(
			groupLayout.createParallelGroup(Alignment.LEADING)
				.addGroup(groupLayout.createSequentialGroup()
					.addContainerGap()
					.addGroup(groupLayout.createParallelGroup(Alignment.LEADING)
						.addComponent(lblThisEmailAddress, GroupLayout.PREFERRED_SIZE, 339, GroupLayout.PREFERRED_SIZE)
						.addComponent(btnOk, Alignment.TRAILING)
						.addGroup(groupLayout.createSequentialGroup()
							.addGroup(groupLayout.createParallelGroup(Alignment.LEADING)
								.addComponent(lblKeyMaterialsFolder)
								.addComponent(lblPrivateEmail))
							.addPreferredGap(ComponentPlacement.RELATED)
							.addGroup(groupLayout.createParallelGroup(Alignment.LEADING)
								.addComponent(privateEmailTextField, GroupLayout.PREFERRED_SIZE, 254, GroupLayout.PREFERRED_SIZE)
								.addGroup(groupLayout.createSequentialGroup()
									.addComponent(parentFolderTextField, GroupLayout.DEFAULT_SIZE, 254, Short.MAX_VALUE)
									.addGap(8)
									.addComponent(btnBrowse)))))
					.addContainerGap())
		);
		groupLayout.setVerticalGroup(
			groupLayout.createParallelGroup(Alignment.LEADING)
				.addGroup(groupLayout.createSequentialGroup()
					.addContainerGap()
					.addGroup(groupLayout.createParallelGroup(Alignment.BASELINE)
						.addComponent(lblKeyMaterialsFolder)
						.addComponent(parentFolderTextField, GroupLayout.PREFERRED_SIZE, 29, GroupLayout.PREFERRED_SIZE)
						.addComponent(btnBrowse))
					.addPreferredGap(ComponentPlacement.RELATED)
					.addGroup(groupLayout.createParallelGroup(Alignment.BASELINE)
						.addComponent(lblPrivateEmail)
						.addComponent(privateEmailTextField, GroupLayout.PREFERRED_SIZE, 29, GroupLayout.PREFERRED_SIZE))
					.addPreferredGap(ComponentPlacement.UNRELATED)
					.addComponent(lblThisEmailAddress, GroupLayout.PREFERRED_SIZE, 46, GroupLayout.PREFERRED_SIZE)
					.addPreferredGap(ComponentPlacement.RELATED, 146, Short.MAX_VALUE)
					.addComponent(btnOk)
					.addContainerGap())
		);
		setLayout(groupLayout);
	}

	public JTextField getParentFolderTextField() {
		return parentFolderTextField;
	}
}
