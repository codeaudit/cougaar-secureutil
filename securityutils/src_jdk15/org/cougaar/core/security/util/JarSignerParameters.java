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


package org.cougaar.core.security.util;

import com.sun.jarsigner.ContentSignerParameters;
import java.net.URI;
import java.security.cert.X509Certificate;
import java.util.zip.ZipFile;

public class JarSignerParameters
implements ContentSignerParameters
{
  
  public JarSignerParameters(String as[], URI uri, X509Certificate x509certificate, byte abyte0[], String s, X509Certificate ax509certificate[], byte abyte1[], 
      ZipFile zipfile)
  {
    if(abyte0 == null || s == null || ax509certificate == null)
    {
      throw new NullPointerException();
    } else
    {
      args = as;
      tsa = uri;
      tsaCertificate = x509certificate;
      signature = abyte0;
      signatureAlgorithm = s;
      signerCertificateChain = ax509certificate;
      content = abyte1;
      source = zipfile;
      return;
    }
  }
  
  public String[] getCommandLine()
  {
    return args;
  }
  
  public URI getTimestampingAuthority()
  {
    return tsa;
  }
  
  public X509Certificate getTimestampingAuthorityCertificate()
  {
    return tsaCertificate;
  }
  
  public byte[] getSignature()
  {
    return signature;
  }
  
  public String getSignatureAlgorithm()
  {
    return signatureAlgorithm;
  }
  
  public X509Certificate[] getSignerCertificateChain()
  {
    return signerCertificateChain;
  }
  
  public byte[] getContent()
  {
    return content;
  }
  
  public ZipFile getSource()
  {
    return source;
  }
  
  private String args[];
  private URI tsa;
  private X509Certificate tsaCertificate;
  private byte signature[];
  private String signatureAlgorithm;
  private X509Certificate signerCertificateChain[];
  private byte content[];
  private ZipFile source;
}
