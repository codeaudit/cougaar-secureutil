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
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import org.cougaar.util.log.Logger;
import org.cougaar.util.log.LoggerFactory;


/**
 * @author srosset
 *
 * A dummy SSLSocketFactory that does not check the trust of server-side certificates.
 */
public class BasicSSLSocketFactory extends SSLSocketFactory {
  
  private static final String SSLContextProtocol = "TLS";
  private SSLSocketFactory mySocketFactory;
  private static SSLSocketFactory singleton = new BasicSSLSocketFactory();
  private static Logger log = LoggerFactory.getInstance().createLogger(BasicSSLSocketFactory.class);
  
  /**
   * Constructor
   */
  private BasicSSLSocketFactory() {
    try {
      SSLContext context = SSLContext.getInstance(SSLContextProtocol);
      TrustManager[] tm = {new BasicTrustManager()};
      context.init(null, tm, null);
      mySocketFactory = context.getSocketFactory();
    }
    catch (Exception ex) {
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
    if (log.isDebugEnabled()) {
      log.debug("Creating socket: " + host + ":" + port);
    }
    return mySocketFactory.createSocket(socket, host, port, autoClose);
  }
  /* (non-Javadoc)
   * @see javax.net.SocketFactory#createSocket(java.lang.String, int)
   */
  public Socket createSocket(String host, int port) throws IOException, UnknownHostException {
    if (log.isDebugEnabled()) {
      log.debug("Creating socket: " + host + ":" + port);
    }
    return mySocketFactory.createSocket(host, port);
  }
  /* (non-Javadoc)
   * @see javax.net.SocketFactory#createSocket(java.net.InetAddress, int)
   */
  public Socket createSocket(InetAddress host, int port) throws IOException {
    if (log.isDebugEnabled()) {
      log.debug("Creating socket: " + host + ":" + port);
    }
    return mySocketFactory.createSocket(host, port);
  }
  /* (non-Javadoc)
   * @see javax.net.SocketFactory#createSocket(java.lang.String, int, java.net.InetAddress, int)
   */
  public Socket createSocket(String host, int port, InetAddress localHost, int localPort) throws IOException, UnknownHostException {
    if (log.isDebugEnabled()) {
      log.debug("Creating socket: " + host + ":" + port);
    }
    return mySocketFactory.createSocket(host, port, localHost, localPort);
  }

  /* (non-Javadoc)
   * @see javax.net.SocketFactory#createSocket(java.net.InetAddress, int, java.net.InetAddress, int)
   */
  public Socket createSocket(InetAddress host, int port, InetAddress localHost, int localPort) throws IOException {
    if (log.isDebugEnabled()) {
      log.debug("Creating socket: " + host + ":" + port);
    }
    return mySocketFactory.createSocket(host, port, localHost, localPort);
  }
  
  /**
   * @author srosset
   *
   * A dummy TrustManager that accepts all certificates.
   */
  private class BasicTrustManager implements X509TrustManager
  {
    private X509Certificate[] certs = {};
    
    /* (non-Javadoc)
     * @see javax.net.ssl.X509TrustManager#getAcceptedIssuers()
     */
    public X509Certificate[] getAcceptedIssuers() {
      if (log.isDebugEnabled()) {
        log.debug("getAcceptedIssuers()");
      }
      return certs;
    }
    /* (non-Javadoc)
     * @see javax.net.ssl.X509TrustManager#checkClientTrusted(java.security.cert.X509Certificate[], java.lang.String)
     */
    public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
      if (log.isDebugEnabled()) {
        String name = null;
        if (chain != null) {
          name = chain[0].getSubjectDN().getName();
        }
        log.debug("checkClientTrusted: " + name + " - authType:" + authType);
      }
    }

    /* (non-Javadoc)
     * @see javax.net.ssl.X509TrustManager#checkServerTrusted(java.security.cert.X509Certificate[], java.lang.String)
     */
    public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
      if (log.isDebugEnabled()) {
        String name = null;
        if (chain != null) {
          name = chain[0].getSubjectDN().getName();
        }
        log.debug("checkServerTrusted: " + name + " - authType:" + authType);
      }
    }
  }
}
