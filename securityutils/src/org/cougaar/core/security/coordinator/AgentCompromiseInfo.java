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

package org.cougaar.core.security.coordinator;

import java.io.Serializable;

public class AgentCompromiseInfo implements Serializable {
  public final static String SENSOR = "SENSOR";
  public final static String ACTION = "ACTION";
  public final static String COMPLETION_CODE = "COMPLETION_CODE";

  // THREAT CON LEVEL FOR COMPROMISE
  public final static String NONE = "NONE";
  public final static String MODERATE = "MODERATE";
  public final static String SEVERE = "SEVERE";

  // Completion code definition
  public final static String COMPLETED = "COMPLETED";
  public final static String FAILED = "FAILED";  

  long timestamp;
  String agent;
  String node;
  String host;
  String diagnosis;
  String type;

  public AgentCompromiseInfo(String type, long timestamp, String agent,
    String node, String host, String diagnosis) {
    this.type = type;
    this.timestamp = timestamp;
    this.agent = agent;
    this.node = node;
    this.host = host;
    this.diagnosis = diagnosis;
  }

  public AgentCompromiseInfo(String type, String agent, String diagnosis) {
    this.type = type;
    this.agent = agent;
    this.diagnosis = diagnosis;
  }

  public void setType(String type) {
    this.type = type;
  }

  public String getType() {
    return type;
  }

  public long getTimestamp() {
    return timestamp;
  }

  public String getSourceAgent() {
    return agent;
  }

  public String getSourceNode() {
    return node;
  }

  public String getSourceHost() {
    return host;
  }

  public String getDiagnosis() {
    return diagnosis;
  }
}
