package burp;

/**
 * All extensions must implement this interface.
 * Implementors must be called exactly "BurpExtender" in the package "burp".
 */
public interface IBurpExtender {
    /**
     * This method is invoked when the extension is loaded. It registers an 
     * instance of the IBurpExtenderCallbacks interface, providing methods that 
     * may be invoked by the extension to perform various actions.
     * 
     * @param callbacks An IBurpExtenderCallbacks object.
     */
    void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks);
}