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

import java.io.InputStream;
import java.io.IOException;
import java.util.Iterator;
import java.util.Vector;


import javax.xml.parsers.DocumentBuilder; 
import javax.xml.parsers.DocumentBuilderFactory;  
import javax.xml.parsers.ParserConfigurationException;

import org.cougaar.util.ConfigFinder;
import org.cougaar.util.log.Logger;
import org.cougaar.util.log.LoggerFactory;


import org.w3c.dom.Document;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;

import org.xml.sax.SAXException;


public class WebProxyConfig
{
  private static Logger _log = null;
  static {
    _log = LoggerFactory.getInstance().createLogger(ProxyURLConnection.class);
  }
  private final static String file = "WebProxyMappings.xml";
  private static Vector mappings = new Vector();

  public static void init()
    throws IOException
  {
    ConfigFinder cf = ConfigFinder.getInstance();
    InputStream is = cf.open(file);
    parse(is);
  }

  private static void parse(InputStream is)
    throws IOException
  {
    DocumentBuilderFactory factory =
      DocumentBuilderFactory.newInstance();
    if (_log.isDebugEnabled()) {
      _log.debug("found a factory = " + factory);
    }
    
    try {
      DocumentBuilder builder = factory.newDocumentBuilder();
      if (_log.isDebugEnabled()) {
        _log.debug("new document builder = " + builder);
      }
      Document document = builder.parse(is);
      Node head = document.getFirstChild();
      if (!head.getNodeName().equals("mappings")) {
        if (_log.isDebugEnabled()) {
          _log.warn("Head name actually = " + head.getNodeName());
        }
        throw new IOException("Wrong type of file");
      }     
      for (Node cipher = head.getFirstChild();
           cipher != null;
           cipher = cipher.getNextSibling()) {
        addMapping(cipher);
      }
      is.close();
      if (_log.isDebugEnabled()) {
        _log.debug("document = " + document);
      }
    } catch (SAXException sxe) {
      // Error generated during parsing)
      Exception  x = sxe;
      if (sxe.getException() != null) {
        x = sxe.getException();
      }
      _log.error("Exception getting web proxy configuration", x);
    } catch (ParserConfigurationException pce) {
      // Parser with specified options can't be built
      _log.error("Exception getting web proxy configuration", pce);
    } catch (IOException ioe) {
      // I/O error
      _log.error("Exception getting web proxy configuration", ioe);

    }
  }

  private static void addMapping(Node mapping)
  {
    printNode(mapping);
    if (!mapping.getNodeName().equals("redirect") ||
        (mapping.getNodeType() != Node.ELEMENT_NODE)) {
      if (_log.isDebugEnabled()) {
        _log.debug("skipping node");
      }
      return;
    }
    NamedNodeMap nnm = mapping.getAttributes();
    if (nnm == null) {
      if (_log.isDebugEnabled()) {
        _log.debug("No attributes - skipping");
      }
      return;
    }
    String prefix  = nnm.getNamedItem("prefix").getNodeValue();
    String prepend = nnm.getNamedItem("prepend").getNodeValue();
    if (prefix == null || prepend == null) {
      if (_log.isDebugEnabled()) {
        _log.debug("Incomplete attributes - skipping");
      }
      return;
    }
    mappings.add(new Redirect(prefix,prepend));
    if (_log.isDebugEnabled()) {
      _log.debug("Added new redirect " + prefix + " --> " + prepend);
    }
  }

  private static void printNode(Node node)
  {
    if (_log.isDebugEnabled()) {
      _log.debug("------------Node---------------");
      _log.debug(" name = " + node.getNodeName());
      _log.debug(" value = " + node.getNodeValue());
      _log.debug(" type = " + node.getNodeType());
      NamedNodeMap nnm = node.getAttributes();
      if (nnm == null) { 
        _log.debug("No attributes");
      } else {
        for (int i = 0; i < nnm.getLength(); i++) {
          Node attr = nnm.item(i);
          _log.debug("  attribute name = " + attr.getNodeName());
          _log.debug("  attribute value = " + attr.getNodeValue());
          _log.debug("  attribute type = " + attr.getNodeType());
        }
      }
      _log.debug("---------That's all---------------");
    }
  }

  public static String map(String uri)
  {
    if (_log.isDebugEnabled()) {
      _log.debug("Searching for mapping for name  " + uri);
    }
    for (Iterator mappingIt = mappings.iterator();
         mappingIt.hasNext(); ) {
      Redirect rd = (Redirect) mappingIt.next();
      String mapped = rd.map(uri);
      if (mapped != null) {
        if (_log.isDebugEnabled()) {
          _log.debug("mapped name " + uri + " to " + mapped);
        }
        return mapped;
      }
    }
    if (_log.isDebugEnabled()) {
      _log.debug("No mapping  found for " + uri);
    }
    return null;
  }
}
