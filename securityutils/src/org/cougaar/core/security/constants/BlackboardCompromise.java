/*
 * Created on Aug 13, 2004
 *
 * To change the template for this generated file go to
 * Window - Preferences - Java - Code Generation - Code and Comments
 */
package org.cougaar.core.security.constants;


/**
 * @author srosset
 *
 * To change the template for this generated type comment go to
 * Window - Preferences - Java - Code Generation - Code and Comments
 */
public interface BlackboardCompromise {

  /**Constant for revoke session verb*/
  public static final String REVOKE_SESSION_KEY_VERB="RevokeSessionKey";

  /**Constant for verb to revoke agent cert*/
  public static final String REVOKE_AGENT_CERT_VERB="RevokeAgentCert";
  public static final String CA_DN_PREP ="Agent CA DN List";
  public static final String FOR_AGENT_PREP = "for agent";
  public static final String COMPROMISE_TIMESTAMP_PREP="timestamp";

  // Constants for sensor
  public static final String THREAT_ALERT_NONE = "NONE";
  public static final String THREAT_ALERT_MODERATE = "MODERATE";
  public static final String THREAT_ALERT_SEVERE = "SEVERE";
}
