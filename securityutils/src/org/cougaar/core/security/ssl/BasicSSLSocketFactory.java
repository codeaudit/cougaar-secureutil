/* 
 * <copyright> 
 *  Copyright 1999-2004 Cougaar Software, Inc.
 *  under sponsorship of the Defense Advanced Research Projects 
 *  Agency (DARPA). 
 *  
 *  You can redistribute this software and/or modify it under the
 *  terms of the Cougaar Open Source License as published on the
 *  Cougaar Open Source Website (www.cougaar.org).  
 *  
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *  A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *  OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *  LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *  DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *  THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *  
 * </copyright> 
 */ 
package org.cougaar.core.security.ssl;

import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.NoSuchAlgorithmException;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import org.cougaar.util.log.Logger;
import org.cougaar.util.log.LoggerFactory;


public class BasicSSLSocketFactory extends SSLSocketFactory {
  
  private static final String SSLContextProtocol = "TLS";
  private SSLSocketFactory mySocketFactory;
  private static SSLSocketFactory singleton = new BasicSSLSocketFactory();
  private static Logger log = LoggerFactory.getInstance().createLogger(BasicSSLSocketFactory.class);
  
  private BasicSSLSocketFactory() {
    try {
      SSLContext context = SSLContext.getInstance(SSLContextProtocol);
      mySocketFactory = context.getSocketFactory();
    }
    catch (NoSuchAlgorithmException ex) {
      if (log.isErrorEnabled()) {
        log.error("Unable to instantiate SSL socket factory", ex);
      }
    }
  }
  
  public static SSLSocketFactory getInstance() {
    return singleton;
  }
  
  /* (non-Javadoc)
   * @see javax.net.ssl.SSLSocketFactory#getDefaultCipherSuites()
   */
  public String[] getDefaultCipherSuites() {
    return mySocketFactory.getDefaultCipherSuites();
  }
  /* (non-Javadoc)
   * @see javax.net.ssl.SSLSocketFactory#getSupportedCipherSuites()
   */
  public String[] getSupportedCipherSuites() {
    return mySocketFactory.getSupportedCipherSuites();
  }
  /* (non-Javadoc)
   * @see javax.net.ssl.SSLSocketFactory#createSocket(java.net.Socket, java.lang.String, int, boolean)
   */
  public Socket createSocket(Socket socket, String host, int port, boolean autoClose) throws IOException {
    return mySocketFactory.createSocket(socket, host, port, autoClose);
  }
  /* (non-Javadoc)
   * @see javax.net.SocketFactory#createSocket(java.lang.String, int)
   */
  public Socket createSocket(String host, int port) throws IOException, UnknownHostException {
    return mySocketFactory.createSocket(host, port);
  }
  /* (non-Javadoc)
   * @see javax.net.SocketFactory#createSocket(java.net.InetAddress, int)
   */
  public Socket createSocket(InetAddress host, int port) throws IOException {
    return mySocketFactory.createSocket(host, port);
  }
  /* (non-Javadoc)
   * @see javax.net.SocketFactory#createSocket(java.lang.String, int, java.net.InetAddress, int)
   */
  public Socket createSocket(String host, int port, InetAddress localHost, int localPort) throws IOException, UnknownHostException {
    return mySocketFactory.createSocket(host, port, localHost, localPort);
  }

  /* (non-Javadoc)
   * @see javax.net.SocketFactory#createSocket(java.net.InetAddress, int, java.net.InetAddress, int)
   */
  public Socket createSocket(InetAddress host, int port, InetAddress localHost, int localPort) throws IOException {
    return mySocketFactory.createSocket(host, port, localHost, localPort);
  }
  
}