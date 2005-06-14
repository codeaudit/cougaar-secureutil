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


package org.cougaar.core.security.util.webproxy;

import java.net.URLStreamHandler;
import java.net.URLStreamHandlerFactory;
import java.util.StringTokenizer;

import org.cougaar.core.security.util.webproxy.http.Handler;
import org.cougaar.util.log.Logger;
import org.cougaar.util.log.LoggerFactory;


/**
 * This is a factory that takes a protocol and generates a
 * URLStreamHandler.  
 *
 * The ProxyURLStreamHandler then takes a URL and returns a
 * ProxyURLStreamHandler.  The ProxyURLStreamHandler is an object that knows how
 * to make a connection for a paticular protocol type (e.g. ftp, http,
 * jar, jndi). This factory constructs URLStreamHandlers for the http
 * and jndi protocols.  Documentation of the place of this factory in
 * the lifecycle of a URL can be found in the javadocs for the
 *
 *     URL(String protocol,
 *         String host,
 *         int port,
 *         String file)
 *
 * constructor.  
 */
class ProxyURLStreamHandlerFactory implements URLStreamHandlerFactory
{
  private static Logger _log = null;
  private static final String HANDLER_PROP_NAME = "java.protocol.handler.pkgs";
  //private static final String DEFAULT_HANDLER = "sun.net.www.protocol";
  
  static {
    _log = LoggerFactory.getInstance().createLogger(ProxyURLStreamHandlerFactory.class);
  }

  /**
   * This method provides URLStreamHandlers for the jndi and http
   * protoocols.
   *
   * The http handler is here so that daml pages can be loaded
   * directly from the cougaar config files rather than off the
   * network.
   *
   * The jndi handler is here for support of the tomcat engine.  This
   * webproxy prevents tomcat from loading its own jndi protocol
   * support so we must implement it here.  This needs testing - I did
   * the obvious thing but it is a little different than what tomcat
   * does. 
   */

  public URLStreamHandler createURLStreamHandler(String protocol) {
    if (_log.isDebugEnabled()) {
      _log.debug("+++++++++++++++++++++++++++++++++++++++++++++++++");
      _log.debug("Protocol = " + protocol);
    }
    if (protocol.equals("http")) {
      if (_log.isDebugEnabled()) {
        _log.debug("Returning the proxy handler");
      }
      return new Handler();
    } else if (protocol.equals("jndi")) {
      // Tomcat JNDI factory.
      return new org.apache.naming.resources.DirContextURLStreamHandler();
    } else {
      try {
        return getURLStreamHandler(protocol);
      }
      catch (Exception e) {
        _log.error("Unable to parse property", e);
        return null;
      }
    }
  }

  /**
   * @param protocol
   * @return
   */
  private URLStreamHandler getURLStreamHandler(String protocol) {
    String prop = "";
    try {
      prop = System.getProperty(HANDLER_PROP_NAME);
      if (prop == null) {
        prop = "";
      }
    }
    catch (Exception e) {
      _log.error("Unable to read property: " + HANDLER_PROP_NAME, e);
    }
    //prop = prop + (prop.length() > 0 ? "|" : "") + DEFAULT_HANDLER;
    
    StringTokenizer st = new StringTokenizer(prop, "|");
    while (st.hasMoreTokens()) {
      String pkgName = st.nextToken();
      String s1 = (new StringBuffer()).append(pkgName).append(".").append(protocol).append(".Handler").toString();
      Class class1;
      if (_log.isDebugEnabled()) {
        _log.debug("Trying to load " + s1);
      }
      try {
        class1 = Class.forName(s1);
        return (URLStreamHandler)class1.newInstance();
      } catch (Exception e) {
        if (_log.isDebugEnabled()) {
          _log.debug("Load of " + s1 + " failed: " + e.getMessage());
        }
        continue;
      }
    }
    if (_log.isDebugEnabled()) {
      _log.debug("using the default handler");
    }
    return null;
  }
}
