/*
 * Created on Aug 12, 2004
 *
 * To change the template for this generated file go to
 * Window - Preferences - Java - Code Generation - Code and Comments
 */
package org.cougaar.core.security.monitoring.publisher;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.List;

import org.cougaar.core.security.monitoring.event.FailureEvent;
import org.cougaar.util.ConfigFinder;
import org.cougaar.util.log.Logger;
import org.cougaar.util.log.LoggerFactory;


/**
 * @author srosset
 *
 * To change the template for this generated type comment go to
 * Window - Preferences - Java - Code Generation - Code and Comments
 */
public class SecurityEventPublisher {
  private static List    m_eventTypes = new ArrayList();
  private static List    m_events = new ArrayList();
  private static Logger  _log;
  
  static {
    _log = LoggerFactory.getInstance().createLogger(SecurityEventPublisher.class);
    try {
      /*
       * The IdmefEventListener.conf file should have the following format:
       * <event class name 1>  <sensor class name 1>
       * <event class name 2>  <sensor class name 2>
       * ...
       * Where <event class name> is a subclass of FailureEvent
       * and <sensor class name> is a subclass of SensorPlugin 
       */
      InputStream listenersIs = ConfigFinder.getInstance().open("IdmefEventListener.conf");
      if (listenersIs != null) {
        if (_log.isDebugEnabled()) {
          _log.debug("Reading IDMEF event listeners from " + listenersIs);
        }
        readIdmefListeners(listenersIs);
      } else {
        if (_log.isInfoEnabled()) {
          _log.info("IdmefEventListener.conf does not exist -- no IDMEF listeners");
        }
      }
    } catch (Exception e) {
      if (_log.isWarnEnabled()) {
        _log.warn("Couldn't load IDMEF listeners from file: ", e);
      }
    }
  }
  
  /* MessageFailureEvent:    MessageFailureSensor
   * LoginFailureEvent:      LoginFailureSensor
   * DataFailureEvent:       DataProtectionSensor
   */
  public static void publishEvent(FailureEvent event) {
    synchronized(m_events) {
        // Event listener has not been configured yet.
        // Queue messages.
        m_events.add(event);
    }
  }
  
  /**
   * @param listenersIs
   */
  private static void readIdmefListeners(InputStream listenersIs) {
    BufferedReader br = new BufferedReader(new InputStreamReader(listenersIs));
    String line = null;
    try {
      while ( (line = br.readLine()) != null) {
        
      }
    } catch (IOException e) {
      if (_log.isErrorEnabled()) {
        _log.error("Unable to read IDMEF listeners: " + e);
      }
    }
  }
}
