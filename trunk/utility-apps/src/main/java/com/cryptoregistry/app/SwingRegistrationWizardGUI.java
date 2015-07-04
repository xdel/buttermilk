/*
 *  This file is part of Buttermilk
 *  Copyright 2011-2015 David R. Smith All Rights Reserved.
 *
 */
package com.cryptoregistry.app;

import java.awt.Color;
import java.awt.Dimension;
import java.awt.Image;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.image.BufferedImage;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;

import javax.imageio.ImageIO;
import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.JFrame;
import javax.swing.JMenu;
import javax.swing.JMenuBar;
import javax.swing.JMenuItem;
import javax.swing.JPanel;
import javax.swing.JTabbedPane;
import javax.swing.UIManager;
import javax.swing.UIManager.LookAndFeelInfo;
import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;

import asia.redact.bracket.properties.Properties;

/**
 * UI for registration
 * 
 * @author Dave
 *
 */
public class SwingRegistrationWizardGUI {
	
	 public static JTabbedPane tabbedPane;
	 public static ShowHelpPanel showHelpPanel;
     public static SettingsPanel settingsPanel;
     public static RegHandlePanel regHandlePanel;
     public static CreateKeyPanel createKeyPanel;
     public static PersonalContactPanel personalContactPanel;
     public static BusinessContactPanel businessContactPanel;
     public static WebsiteContactPanel websiteContactPanel;
     public static SignaturePanel signaturePanel;
     public static KeyMaterialsPanel keyMaterialsPanel;
     
     public static KM km;
     public static RequestSession session;
     
     private static class IconLister {
     
	    public IconLister() {}

		public final List<Image> getIconList() {
	    	 
	    	  List<Image> iconList = null;
			try {
				 BufferedImage icon16 = ImageIO.read(this.getClass().getResource("/hand-trans16.png"));
				 BufferedImage icon32 = ImageIO.read(this.getClass().getResource("/hand-trans32.png"));
				 BufferedImage icon64 = ImageIO.read(this.getClass().getResource("/hand-trans64.png"));
				  iconList = new ArrayList<Image>();
				  iconList.add(icon16);
				  iconList.add(icon32);
				  iconList.add(icon64);
			  
			} catch (IOException e) {
				throw new RuntimeException(e);
			}
			  return iconList;
	     }
     }
     
     private static JMenuBar createMenuBar(Properties props) {
    	 
    	 final Properties myprops = props;
    	 
    	 JMenuBar menuBar = new JMenuBar();

    	//Build the first menu.
    	JMenu fileMenu = new JMenu("File");
    	menuBar.add(fileMenu);
    	
    	JMenu utilityMenu = new JMenu("Utility");
    	menuBar.add(utilityMenu);
    	JMenuItem item0 = new JMenuItem("Binary Entropy (Croll's Method)");
    	utilityMenu.add(item0);
    	item0.addActionListener(new ActionListener() {

			@Override
			public void actionPerformed(ActionEvent e) {
				JFrame myframe = new JFrame();
				myframe.setIconImages(new IconLister().getIconList());
				new EntropyDialog(myframe, "Binary Entropy");
			}
    		
    	});
    	
    	menuBar.add(Box.createHorizontalGlue());
    	
    	JMenu aboutMenu = new JMenu("About");
    	menuBar.add(aboutMenu);
    	
    	JMenuItem itemAbout = new JMenuItem("About This Application");
    	aboutMenu.add(itemAbout);
    	itemAbout.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
			            	new AboutFrame(myprops);
			}
    	});
    	
    	return menuBar;
     }
     

	 private static void createAndShowGUI(Properties props) {
		 
		 km = new KM();
		
		 try {
			    for (LookAndFeelInfo info : UIManager.getInstalledLookAndFeels()) {
			        if ("Nimbus".equals(info.getName())) {
			            UIManager.setLookAndFeel(info.getClassName());
			            break;
			        }
			    }
			} catch (Exception e) {}
		 
		
		 
	        //Create and set up the window.
	        JFrame frame = new JFrame("cryptoregistry.com - Registration Key Materials Wizard");
	        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
	      //  frame.setPreferredSize(new Dimension(970,570));
	        frame.setIconImages(new IconLister().getIconList());
	        frame.setJMenuBar(createMenuBar(props));
	       
	        tabbedPane = new JTabbedPane();
	        tabbedPane.setPreferredSize(new Dimension(970,350));
	        tabbedPane.setBackground(new Color(208, 228, 254));
	       
	        showHelpPanel = new ShowHelpPanel(props);
	        settingsPanel = new SettingsPanel(props);
	        regHandlePanel = new RegHandlePanel(props);
	        createKeyPanel = new CreateKeyPanel(props);
	        personalContactPanel = new PersonalContactPanel();
	        businessContactPanel = new BusinessContactPanel();
	        websiteContactPanel = new WebsiteContactPanel();
	        signaturePanel = new SignaturePanel(props);
	        keyMaterialsPanel = new KeyMaterialsPanel(props);
	        
	    	settingsPanel.setBorder(BorderFactory.createEmptyBorder(15, 15, 15, 15));
	    	settingsPanel.setBackground(new Color(208, 228, 254));
	    	regHandlePanel.setBorder(BorderFactory.createEmptyBorder(15, 15, 15, 15));
	    	regHandlePanel.setBackground(new Color(208, 228, 254));
	    	createKeyPanel.setBorder(BorderFactory.createEmptyBorder(15, 15, 15, 15));
	    	createKeyPanel.setBackground(new Color(208, 228, 254));
	    	personalContactPanel.setBorder(BorderFactory.createEmptyBorder(15, 15, 15, 15));
	    	personalContactPanel.setBackground(new Color(208, 228, 254));
	    	businessContactPanel.setBorder(BorderFactory.createEmptyBorder(15, 15, 15, 15));
	    	businessContactPanel.setBackground(new Color(208, 228, 254));
	    	websiteContactPanel.setBorder(BorderFactory.createEmptyBorder(15, 15, 15, 15));
	    	websiteContactPanel.setBackground(new Color(208, 228, 254));
	    	signaturePanel.setBorder(BorderFactory.createEmptyBorder(15, 15, 15, 15));
	    	signaturePanel.setBackground(new Color(208, 228, 254));
	        
	        tabbedPane.addTab("Introduction", showHelpPanel);
	        tabbedPane.addTab("Settings", settingsPanel);
	        tabbedPane.addTab("Select Registration Handle", regHandlePanel);
	        tabbedPane.addTab("Initial Key", createKeyPanel);
	        tabbedPane.addTab("Personal Contact", personalContactPanel);
	        tabbedPane.addTab("Business Contact", businessContactPanel);
	        tabbedPane.addTab("Website Contact", websiteContactPanel);
	        tabbedPane.addTab("Signature", signaturePanel);
	        tabbedPane.addTab("Generated Key Materials", keyMaterialsPanel);
	        tabbedPane.setBorder(BorderFactory.createLineBorder(Color.BLACK));
	        
	        ChangeListener changeListener = new ChangeListener() {

				@Override
				public void stateChanged(ChangeEvent e) {
					 JTabbedPane sourceTabbedPane = (JTabbedPane) e.getSource();
				        int index = sourceTabbedPane.getSelectedIndex();
				        switch(index){
				        	case 0: {
				        		// introduction tab
				        		break;
				        	}
				        	case 1:{
				        		settingsPanel.getParentFolderTextField().requestFocusInWindow();
				        		break;
				        	}
				        	case 2:{
				        		regHandlePanel.getRegHandleTextField().requestFocusInWindow();
				        		break;
				        	}
				        	case 3:{
				        		createKeyPanel.getPassword0().requestFocusInWindow();
				        		break;
				        	}
				        	case 4:{
				        		personalContactPanel.getTextField().requestFocusInWindow();
				        		break;
				        	}
				        	case 5:{
				        		businessContactPanel.getTextField().requestFocusInWindow();
				        		break;
				        	}
				        	case 6:{
				        		websiteContactPanel.getTextField().requestFocusInWindow();
				        		break;
				        	}
				        	case 7:{
				        		signaturePanel.getTextArea().requestFocusInWindow();
				        		break;
				        	}
				        	case 8:{
				        		keyMaterialsPanel.getRequestTextPane().requestFocusInWindow();
				        		break;
				        	}
				        	default: {}
				        }
					
				}
	        };
	        
	        tabbedPane.addChangeListener(changeListener);
	        
	        JPanel outer = new JPanel();
	        outer.setLayout(new BoxLayout(outer, BoxLayout.LINE_AXIS));
	        outer.add(tabbedPane);
	        outer.add(new ChecklistPanel(km,props));
	        outer.setBackground(new Color(208, 228, 254));
	        
	        frame.getContentPane().add(outer);
	        
	        //Display the window.
	        frame.pack();
	        frame.setVisible(true);
	    }
	 
	    public static void main(String[] args) {
	        javax.swing.SwingUtilities.invokeLater(new Runnable() {
	            public void run() {
	            	InputStream in = Thread.currentThread()
	            			.getContextClassLoader().getResourceAsStream("regwizard.properties");
	            	Properties props = Properties.Factory.getInstance(in);
	                createAndShowGUI(props);
	            }
	        });
	    }

}
