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


package org.cougaar.core.security.handoff.blackboard;

import java.io.Serializable;
import java.util.List;


/**
 * @author rtripathi
 *
 */
public class HandOffUnRegistration implements Serializable {
  private int cmd ;
  private List communityTypes = null;
  private String enclave =null;

  public HandOffUnRegistration( int command){
    cmd =command;
  }
  
  public HandOffUnRegistration( int command, List communitytypes){
    cmd = command;
    communityTypes = communitytypes ;
  }
  
  public HandOffUnRegistration( int command, String newenclave){
    cmd = command;
    enclave = newenclave;
  }


  public final static int UNREGISTER_SENSOR =1;
  public final static int UNREGISTER_CRL = 2;
  public final static int LEAVE_SECURITYCOMMUNITY = 3;
  public final static int REREGISTER_SENSOR =4;
  public final static int REREGISTER_CRL = 5;
  public final static int JOIN__SECURITYCOMMUNITY = 6;

  public int getCommand(){
    return cmd ;
  }

  public List getCommunityTypes(){
    return communityTypes;
  }
  
  public String getEnclaveName(){
    return enclave;
  }
  
}
