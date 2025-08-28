package burp;

/**
 * This interface is used to provide details about an HTTP service, to which
 * HTTP requests can be sent.
 */
public interface IHttpService {
    
    /**
     * This method returns the hostname or IP address for the service.
     * 
     * @return The hostname or IP address for the service.
     */
    String getHost();
    
    /**
     * This method returns the port number for the service.
     * 
     * @return The port number for the service.
     */
    int getPort();
    
    /**
     * This method returns the protocol for the service.
     * 
     * @return The protocol for the service. Expected values are "http" or 
     * "https".
     */
    String getProtocol();
}