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
package org.cougaar.core.security.policy;

/**
 * @author rliao
 *
 * TODO To change the template for this generated type comment go to
 * Window - Preferences - Java - Code Style - Code Templates
 */
public class CryptoClientPolicyConstants {
	  public static final String IS_CERT_AUTH_ELEMENT = "isCertificateAuthority";
	  public static final String IS_ROOT_CA_ELEMENT = "isRootCA";
	  public static final String CA_KEYSTORE_ELEMENT          = "CA_keystore";
	  public static final String CA_KEYSTORE_PASSWORD_ELEMENT = "CA_keystorePassword";

	  public static final String KEYSTORE_FILE_ELEMENT          = "keystoreFileName";
	  public static final String KEYSTORE_PASSWORD_ELEMENT      = "keystorePassword";
	  public static final String KEYSTORE_USE_SMART_CARD        = "keystoreUseSmartCard";

	  // Trusted Ca attributes
	  public static final String TRUSTED_CA_ELEMENT          = "trustedCA";
	  public static final String CA_URL_ELEMENT              = "CA_URL";
	  public static final String CA_DN_ELEMENT               = "CA_DN";
	  public static final String CERT_DIRECTORY_URL_ELEMENT  = "CertDirectoryURL";
	  public static final String CERT_DIRECTORY_TYPE_ELEMENT = "CertDirectoryType";
	  public static final String CERT_DIRECTORY_PRINCIPAL_ELEMENT = "CertDirectorySecurityPrincipal";
	  public static final String CERT_DIRECTORY_CREDENTIAL_ELEMENT = "CertDirectorySecurityCredential";
	  public static final String CA_INFOURL_ELEMENT          = "CA_infoURL";
	  public static final String CA_REQUESTURL_ELEMENT          = "CA_requestURL";

	  // Certificate Attributes
	  public static final String CERTIFICATE_ATTR_ELEMENT = "certificateAttributes";
	  //public static final String CACERTIFICATE_ATTR_ELEMENT = "caCertificateAttributes";
	  public static final String OU_ELEMENT           = "ou";
	  public static final String O_ELEMENT            = "o";
	  public static final String L_ELEMENT            = "l";
	  public static final String ST_ELEMENT           = "st";
	  public static final String C_ELEMENT            = "c";
	  public static final String DOMAIN_ELEMENT       = "domain";
	  public static final String KEYALGNAME_ELEMENT   = "keyAlgName";
	  public static final String SIGALGNAME_ELEMENT   = "sigAlgName";
	  public static final String KEYSIZE_ELEMENT      = "keysize";
	  public static final String VALIDITY_ELEMENT     = "validity";
	  public static final String ENVELOPE_ELEMENT     = "timeEnvelope";
	  public static final String NODE_IS_SIGNER_ELEMENT = "nodeIsSigner";
}
