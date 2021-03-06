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

import java.math.BigInteger;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.List;

import org.cougaar.core.component.Service;
import org.cougaar.core.security.crypto.CRLKey;
import org.cougaar.core.security.crypto.CertificateStatus;
import org.cougaar.core.security.crypto.CertificateType;

import sun.security.x509.X500Name;
import javax.net.ssl.X509TrustManager;

/** Low-level service to update and retrive certificates and private keys from the Certificate Cache 
 */
public interface CertificateCacheService extends Service {

  Enumeration getAliasList();
  KeyStore getKeyStore();
  List getX500NameFromNameMapping(String cougaarName);
  // boolean  presentInNameMapping(String commonName);
  List getCertificates(X500Name x500Name);
  CertificateStatus addCertificate(CertificateStatus certEntry);
  void addNameToNameMapping(CertificateStatus certStatus);
  void addCertificateToCache(String alias,
			     X509Certificate importCert,
			     PrivateKey privatekey);
  void removeEntryFromCache(String commonName);
  void addSSLCertificateToCache(X509Certificate cert);
  void addPrivateKey(PrivateKey privatekey, CertificateStatus certEntry);
  String findAlias(X500Name adname);
  //void removeEntry(String commonName);
  //void setKeyEntry(PrivateKey key, X509Certificate cert);
  boolean  presentInNameMapping(X500Name dname) ;
  //List getValidPrivateKeys(X500Name x500Name);
  List getPrivateKeys(X500Name x500Name);
  PrivateKey getKey(String alias, char[] pwd) throws KeyStoreException,
                        NoSuchAlgorithmException,
    UnrecoverableKeyException;
  String getCommonName(String alias);
  String getCommonName(X500Name x500Name) ;
  String getCommonName(X509Certificate x509); 
  //List getValidCertificates(X500Name x500Name);
  X509Certificate getCertificate(String alias)throws KeyStoreException;
  PrivateKey getKey(String alias) throws KeyStoreException,
                        NoSuchAlgorithmException,
                        UnrecoverableKeyException;
  void setKeyEntry(String alias, PrivateKey privatekey,
		    X509Certificate[] certificate);
  void setKeyEntry(String alias, PrivateKey privatekey, char[] pwd,
			  Certificate[] certificate) throws KeyStoreException;

  void saveCertificateInTrustedKeyStore(X509Certificate aCertificate,
					String alias);
  X509Certificate[] getTrustedIssuers();
  void deleteEntry(String alias, String commonName);
  void printCertificateCache();
  CertificateStatus addKeyToCache(X509Certificate certificate, PrivateKey key,
				  String alias, CertificateType certType);
  
  boolean setCertificateTrust(X509Certificate certificate, CertificateStatus cs,
			      X500Name name, Hashtable selfsignedCAs);
  Certificate[] getCertificateChain(String alias)throws KeyStoreException ;
  Enumeration getKeysInCache();
  void revokeStatus(BigInteger serialno, String issuerDN, String subjectDN);
  String getDN(CRLKey crlkey);
  String getKeyStorePath();
  String getCaKeyStorePath();
  void updateBigInt2Dn(X509Certificate cert, boolean actionIsPut) ;
  boolean checkRevokedCache(X509Certificate certificate);
  void addToRevokedCache(String issuerDN, BigInteger serialno) ;
  void addTrustListener(X509TrustManager tm);
  void event(String evt);
}
