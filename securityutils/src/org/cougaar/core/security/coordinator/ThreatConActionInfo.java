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

public class ThreatConActionInfo implements Serializable {
  /**
   * Completion code to be set as diagnosis
   */
  public final static String ACTIVE = "ACTIVE";
  public final static String START = "START";  

  /**
   * Preceived threat level for action 
   */
  public final static String LOWSecurity = "LowSecurity";
  public final static String HIGHSecurity = "HighSecurity";  

  /**
   * Preceived threat level for diagnosis 
   */
  public final static String NONEDiagnosis = "None";
  public final static String LOWDiagnosis = "Low";
  public final static String HIGHDiagnosis = "Severe";  

  String communityName;
  String level;
  String diagnosis;

  public ThreatConActionInfo(String communityName, String level) {
    this.communityName = communityName;
    this.level = level;
    diagnosis = START;
  }

  public void setDiagnosis(String diagnosis) {
    this.diagnosis = diagnosis;
  }

  public String getCommunityName() {
    return communityName;
  }

  public String getLevel() {
    return level;
  }

  public String getDiagnosis() {
    return diagnosis;
  }
}
