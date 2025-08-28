package burp;

/**
 * This interface is used by Burp Suite to pass a set of callback methods to extensions. 
 * Extensions can use these methods to perform various actions within Burp.
 */
public interface IBurpExtenderCallbacks {
    
    /**
     * This method is used to set the display name for the extension, which 
     * will be displayed within the user interface.
     *
     * @param name The extension name.
     */
    void setExtensionName(String name);
    
    /**
     * This method is used to write output to the current extension's 
     * standard output stream.
     *
     * @param output The message to write to the output stream.
     */
    void printOutput(String output);
    
    /**
     * This method is used to write output to the current extension's 
     * standard error stream.
     *
     * @param error The message to write to the error stream.
     */
    void printError(String error);
    
    /**
     * This method is used to register a provider of custom tabs within the main 
     * Burp Suite window.
     *
     * @param tab An object created by the extension that provides the custom tab.
     */
    void addSuiteTab(ITab tab);
    
    /**
     * This method is used to register a factory for custom context menu items.
     * When the user invokes a context menu anywhere within Burp, the factory
     * will be passed details of the invocation and asked to provide any custom
     * menu items that should be shown.
     * 
     * @param factory An object implementing the IContextMenuFactory interface.
     */
    void registerContextMenuFactory(IContextMenuFactory factory);
    
    /**
     * This method is used to obtain the current extension's standard output stream.
     *
     * @return The extension's standard output stream.
     */
    java.io.PrintWriter getStdout();
    
    /**
     * This method is used to obtain the current extension's standard error stream.
     *
     * @return The extension's standard error stream.
     */
    java.io.PrintWriter getStderr();
}