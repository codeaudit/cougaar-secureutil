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

package org.cougaar.core.security.services.crypto;

import java.security.PrivateKey;

import org.cougaar.core.component.Service;
import org.cougaar.core.security.policy.TrustedCaPolicy;
import org.cougaar.core.security.policy.CertificateAttributesPolicy;

import sun.security.x509.X500Name;

public interface CertificateRequestorService extends Service {
	/*
	 * dname 						- X500Name of the requested key
	 * keyAlias					- alias of key in store, null if there is no key 
	 * 										and a new one will be made. 
	 * isCACert					- creating a CA key if true
	 * trustedCaPolicy	-	specifies which CA is sending the request to
	 */
  PrivateKey addKeyPair(X500Name dname, String keyAlias,
      boolean isCACert, TrustedCaPolicy trustedCaPolicy);
  /*
   * dname 						- X500Name of the requested key
   * makeKey					- only makes key but not sending request,
   *                    this is a design issue. Host key is required for
   *                    tomcat to run, but node key may not be generated
   * 										at that time, so a self-signed key is generated.
   * trustedCaPolicy 	- specifies which CA is sending the request to
   * @@return					- alias of the generated key
   */
  String generateKeyPair(X500Name dname, boolean makeKey, 
  		CertificateAttributesPolicy certAttribPolicy) throws Exception;
  
}
