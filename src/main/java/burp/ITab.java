package burp;

import java.awt.Component;

/**
 * Extensions that wish to add custom tabs to the main Burp Suite window can 
 * do so by implementing this interface and then calling 
 * IBurpExtenderCallbacks.addSuiteTab().
 */
public interface ITab {
    
    /**
     * Burp uses this method to obtain the caption that should appear on the 
     * custom tab when it is displayed. 
     *
     * @return The caption that should appear on the custom tab.
     */
    String getTabCaption();
    
    /**
     * Burp uses this method to obtain the component that should be used as the 
     * contents of the custom tab when it is displayed.
     *
     * @return The component that should be used as the contents of the custom tab.
     */
    Component getUiComponent();
}