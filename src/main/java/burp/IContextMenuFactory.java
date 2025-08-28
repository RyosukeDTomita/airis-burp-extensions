package burp;

import java.util.List;
import javax.swing.JMenuItem;

/**
 * Extensions that wish to add custom context menu items to various parts of
 * the Burp user interface can do so by implementing this interface and then
 * calling IBurpExtenderCallbacks.registerContextMenuFactory().
 */
public interface IContextMenuFactory {
    
    /**
     * This method will be called by Burp when a context menu is about to be 
     * displayed.
     * 
     * @param invocation An object that implements IContextMenuInvocation that 
     * can be queried to obtain details of the context menu invocation.
     * @return A list of custom menu items (which may include sub-menus,
     * checkbox menu items, etc.) that should be displayed. This method may 
     * return null to indicate that no menu items are required. 
     */
    List<JMenuItem> createMenuItems(IContextMenuInvocation invocation);
}