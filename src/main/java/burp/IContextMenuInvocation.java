package burp;

/**
 * This interface is used when an extension registers a context menu factory.
 * The factory's createMenuItems method receives an instance of this interface,
 * which the extension can query to obtain details about the invocation.
 */
public interface IContextMenuInvocation {
    
    /**
     * This method can be used to retrieve details about the currently 
     * selected message(s). Null is returned if there are no applicable
     * messages (for example, if the context menu was invoked in a non-message
     * context).
     * 
     * @return An array of IHttpRequestResponse objects representing the items
     * that were shown or selected by the user when the context menu was
     * invoked.
     */
    IHttpRequestResponse[] getSelectedMessages();
    
    /**
     * This method can be used to retrieve the bounds of the user's selection
     * into the request or response, if applicable.
     * 
     * @return An array of offsets that indicate the bounds of the user's
     * selection within the current message. This method returns null if there
     * is no current selection.
     */
    int[] getSelectionBounds();
    
    /**
     * This method can be used to retrieve the context within which the menu
     * was invoked.
     * 
     * @return An integer that indicates the context within which the menu was
     * invoked. This will be one of the CONTEXT_* values defined within this
     * interface.
     */
    byte getInvocationContext();
    
    /**
     * Used to indicate that the context menu is being invoked in a message editor.
     */
    byte CONTEXT_MESSAGE_EDITOR_REQUEST = 0;
    
    /**
     * Used to indicate that the context menu is being invoked in a message viewer.
     */
    byte CONTEXT_MESSAGE_VIEWER_REQUEST = 6;
}