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


package org.cougaar.core.security.services.network;

import org.cougaar.core.component.Service;


/**
 * This service represents the state of the network.  It will probably
 * have site or application specific implementations.
 */

public interface NetworkConfigurationService
  extends Service
{
  public final static int ConnectNormal        = 0;
  public final static int ConnectProtectedLan  = 1;
  public final static int ConnectVPNTunnel     = 2;
  public final static String connectNames []
    = {"Normal", "ProtectedLan", "VPNTunnel"};

  /**
   * This routine provides information about how a connection between
   * two agents will be protected by the network infrastructure.  Thus
   * a node may not need to encrypt a message to a remote host because
   * suuch a connection to the remote host will automatically
   * be encrypted by a network gateway between the two hosts. If the
   * connections between the source and the source's gateway or the
   * receiver and the receiver's gateway are secure, then the
   * encryption between the gateways may suffice.
   */

  public int connectionAttributes(String target);
}
