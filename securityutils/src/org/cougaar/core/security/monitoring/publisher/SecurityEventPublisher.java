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
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

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
  /**
   * A Map of Class (FailureEvent class) to Methods.
   */
  private static Map     m_eventTypes = new HashMap();
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
    Method m = (Method) m_eventTypes.get(event.getClass());
    if (m != null) {
      Object o[] = new Object[1];
      o[0] = event;
      try {
        m.invoke(null, o);
      } catch (IllegalArgumentException e) {
        if (_log.isErrorEnabled()) {
          _log.error("Unable to publish event: " + event);
        }
      } catch (IllegalAccessException e) {
        if (_log.isErrorEnabled()) {
          _log.error("Unable to publish event: " + event);
        }
      } catch (InvocationTargetException e) {
        if (_log.isErrorEnabled()) {
          _log.error("Unable to publish event: " + event);
        }
      }
    }
    else {
      if (_log.isDebugEnabled()) {
        _log.debug("Dropping event: " + event);
      }
    }
  }
  
  /**
   * @param listenersIs
   */
  private static void readIdmefListeners(InputStream listenersIs) {
    BufferedReader br = new BufferedReader(new InputStreamReader(listenersIs));
    Pattern p1 = Pattern.compile("(\\S*)\\s*(\\S*)");
    String line = null;
    try {
      while ( (line = br.readLine()) != null) {
        if (line.startsWith("#")) {
          continue;
        }
        Matcher matcher = p1.matcher(line);
        if (matcher.find()) {
          Class eventClass = null;
          Class sensorClass = null;
          Method publishEventMethod = null;
          String eventClassName = matcher.group(1);
          if (eventClassName != null && eventClassName.length() > 0) {
            try {
              eventClass = Class.forName(eventClassName);
            } catch (ClassNotFoundException e1) {
              if (_log.isErrorEnabled()) {
                _log.error("Unable to find event class name: " + eventClassName);
              }
            }
          }
          
          String sensorClassName = matcher.group(2);
          if (sensorClassName != null && sensorClassName.length() > 0) {
            try {
              sensorClass = Class.forName(sensorClassName);
              Class[] params = new Class[1];
              params[0] = FailureEvent.class;
              publishEventMethod = sensorClass.getDeclaredMethod("publishEvent", params);
            } catch (ClassNotFoundException e1) {
              if (_log.isErrorEnabled()) {
                _log.error("Unable to find sensor class: " + eventClassName, e1);
              }
            } catch (SecurityException e) {
              if (_log.isErrorEnabled()) {
                _log.error("Unable to find sensor class: " + eventClassName, e);
              }
            } catch (NoSuchMethodException e) {
              if (_log.isErrorEnabled()) {
                _log.error("Unable to find sensor class: " + eventClassName, e);
              }
            }
          }
          if (eventClass != null && publishEventMethod != null) {
            if (_log.isDebugEnabled()) {
              _log.debug("Adding IDMEF listener: " + eventClassName
                  + " -> " + sensorClassName);
            }
            m_eventTypes.put(eventClass, publishEventMethod);
          }
        }
      }
    } catch (IOException e) {
      if (_log.isErrorEnabled()) {
        _log.error("Unable to read IDMEF listeners: " + e);
      }
    }
  }
}
