package burp;

/**
 * This interface is used to hold details about an HTTP message.
 */
public interface IHttpRequestResponse {
    
    /**
     * This method is used to retrieve the request part of this HTTP message.
     * 
     * @return The request part of this HTTP message, or null if the message
     * only contains a response.
     */
    byte[] getRequest();
    
    /**
     * This method is used to update the request part of this HTTP message.
     * 
     * @param request The new request part of this HTTP message.
     */
    void setRequest(byte[] request);
    
    /**
     * This method is used to retrieve the response part of this HTTP message.
     * 
     * @return The response part of this HTTP message, or null if the message
     * only contains a request, or if no response has been received.
     */
    byte[] getResponse();
    
    /**
     * This method is used to update the response part of this HTTP message.
     * 
     * @param response The new response part of this HTTP message.
     */
    void setResponse(byte[] response);
    
    /**
     * This method is used to retrieve details of the HTTP service for this 
     * HTTP message.
     * 
     * @return An IHttpService object containing details of the HTTP service, 
     * or null if unknown.
     */
    IHttpService getHttpService();
    
    /**
     * This method is used to update details of the HTTP service for this HTTP
     * message.
     * 
     * @param httpService An IHttpService object containing details of the new
     * HTTP service.
     */
    void setHttpService(IHttpService httpService);
}