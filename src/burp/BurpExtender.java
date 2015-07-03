/*
 * Name:           Burp UserAgent
 * Version:        0.3
 * Date:           7/1/2015
 * Author:         Josh Berry - josh.berry@codewatch.org
 * Github:         https://github.com/codewatchorg/BurpUserAgent
 * 
 * Description:    This plugin modifies requests, changing the User-Agent header to match the selected browser.
 * 
*/

package burp;

import java.util.List;
import java.awt.Component;
import javax.swing.JPanel;
import javax.swing.JLabel;
import javax.swing.JButton;
import javax.swing.JComboBox;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.HashMap;
import javax.xml.parsers.*;
import java.io.File;
import org.xml.sax.*;
import org.xml.sax.helpers.*;

public class BurpExtender implements IBurpExtender, ISessionHandlingAction, ITab {

  public IBurpExtenderCallbacks extCallbacks;
  public IExtensionHelpers extHelpers;
  public JPanel bUAPanel;
  private static final String burpUAVersion = "0.3";
  private PrintWriter printOut;
  private String newUA = "Current Browser";
  private int totalAgents = 0;
  private final HashMap<String, String> bUserAgentNames = new HashMap();
  private final ArrayList<String> bUserAgents = new ArrayList<String>();

  /* function for loading XML file of user agents */
  public void loadXML() {
 
    /* setup the SAX parser */
    try {
        SAXParserFactory factory = SAXParserFactory.newInstance();
        SAXParser saxParser = factory.newSAXParser();

        DefaultHandler handler = new DefaultHandler() {
 
            /* setup a handler for each element */
            @Override
            public void startElement(String uri, String localName, String qName, Attributes attributes) throws SAXException {

                /* if the element is useragent, then look for the attributes */
                if (qName.equalsIgnoreCase("useragent")) {
                    
                    /* if the attributes are there, add them to the hashmap and array of values */
                    if (attributes.getQName(0).contains("description") && attributes.getQName(1).contains("useragent") &&
                            !attributes.getValue(0).isEmpty() && !attributes.getValue(1).isEmpty()) {
                        bUserAgents.add(attributes.getValue(0));
                        bUserAgentNames.put(attributes.getValue(0), attributes.getValue(1));
                        totalAgents = totalAgents + 1;
                    }
                }
            }
        };
 
        /* process the XML file */
        saxParser.parse(new File("useragents.xml"), handler);

    } catch (Exception e) {
        e.printStackTrace();
    }
  }
  
  @Override
  public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
    extCallbacks = callbacks;
    extHelpers = extCallbacks.getHelpers();
    extCallbacks.setExtensionName("Burp UserAgent");
    extCallbacks.registerSessionHandlingAction(this);
    printOut = new PrintWriter(extCallbacks.getStdout(), true);
    printHeader();
    
    /* Create the default User-Agent and then load the rest */
    bUserAgents.add("Current Browser");
    bUserAgentNames.put("Current Browser", "Current Browser");
    loadXML();
    printOut.println("Total Loaded Agents: " + String.valueOf(totalAgents));
    
    /* Create a tab to configure User-Agent header values */
    bUAPanel = new JPanel(null);
    JLabel bUALabel = new JLabel();
    final JComboBox bUACbx = new JComboBox(bUserAgents.toArray());
    JButton bUASetHeaderBtn = new JButton("Set Configuration");
    
    /* Set values for the label and User-Agent combo box */
    bUALabel.setText("User-Agent:");
    bUALabel.setBounds(16, 15, 75, 20);
    bUACbx.setBounds(146, 12, 310, 26);
    bUASetHeaderBtn.setBounds(306, 50, 150, 20);
    
    bUASetHeaderBtn.addActionListener(new ActionListener() {
      public void actionPerformed(ActionEvent e) {
        newUA = bUserAgentNames.get(bUACbx.getItemAt(bUACbx.getSelectedIndex()));
        printOut.println("User-Agent header set to: " + newUA + "\n");
      }
    });
    
    /* Initialize defaults */
    bUACbx.setSelectedIndex(0);

    /* Add label and field to tab */
    bUAPanel.add(bUALabel);
    bUAPanel.add(bUACbx);
    bUAPanel.add(bUASetHeaderBtn);
    
    /* Add the tab to Burp */
    extCallbacks.customizeUiComponent(bUAPanel);
    extCallbacks.addSuiteTab(BurpExtender.this);
  }
  
  /* Print to extension output tab */
  public void printHeader() {
      printOut.println("Burp UserAgent: v" + burpUAVersion + "\n====================\nChange the User-Agent header on requests to a specified value.\n\n"
              + "josh.berry@codewatch.org\n\n");
  }
  
  /* Tab caption */
  @Override
  public String getTabCaption() { return "Burp UserAgent"; }

  /* Java component to return to Burp */
  @Override
  public Component getUiComponent() { return bUAPanel; }
  
  /* Action to set in a session rule */
  @Override
  public String getActionName(){ return "Burp UserAgent"; }
  
  /* Action for extension to perform */
  @Override
  public void performAction(IHttpRequestResponse currentRequest, IHttpRequestResponse[] macroItems) {
      
    /* Setup default variables */
    IRequestInfo requestInfo = extHelpers.analyzeRequest(currentRequest);
    List<String> headers = requestInfo.getHeaders();
    String reqRaw = new String(currentRequest.getRequest());
    String reqBody = reqRaw.substring(requestInfo.getBodyOffset());
    Integer uaInHeader = 0;

    /* If the default isn't set, then modify the User-Agent header */
    if (!newUA.startsWith("Current Browser")) {
        
      /* Loop through the headers to add or set values */
      for (int i = 0; i < headers.size(); i++) {
        
        /* Set to the selected user-agent */
        if (headers.get(i).startsWith("User-Agent:") && !headers.get(i).startsWith("User-Agent: " + newUA)) {                
          headers.set(i, "User-Agent: " + newUA);
          uaInHeader = 1;
        }
      }
    }
    
    /* If set to a specific user-agent, but User-Agent wasn't in request, then add */
    if (uaInHeader == 0 && !newUA.startsWith("Current Browser")) {
        headers.add("User-Agent: " + newUA);
    }
    
    /* Build request with bypass headers */
    byte[] message = extHelpers.buildHttpMessage(headers, reqBody.getBytes());

    /* Update Request with New Header */
    currentRequest.setRequest(message);
  }
}