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

import com.sun.jarsigner.ContentSigner;
import java.io.*;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.*;
import java.util.jar.Attributes;
import java.util.jar.Manifest;
import java.util.zip.ZipFile;
import sun.misc.BASE64Encoder;
import sun.security.util.ManifestDigester;
import sun.security.x509.*;
import sun.security.tools.TimestampedSigner;

class SignatureFile
{
  public static class Block
  {
    
    public String getMetaName()
    {
      return blockFileName;
    }
    
    public void write(OutputStream outputstream)
    throws IOException
    {
      outputstream.write(block);
    }
    
    private byte block[];
    private String blockFileName;
    
    Block(SignatureFile signaturefile, PrivateKey privatekey, X509Certificate ax509certificate[], boolean flag, String s, X509Certificate x509certificate, ContentSigner contentsigner, 
        String as[], ZipFile zipfile)
        throws NoSuchAlgorithmException, InvalidKeyException, IOException, SignatureException, CertificateException
        {
      Principal principal = ax509certificate[0].getIssuerDN();
      if(!(principal instanceof X500Name))
      {
        X509CertInfo x509certinfo = new X509CertInfo(ax509certificate[0].getTBSCertificate());
        Principal principal1 = (Principal)x509certinfo.get("issuer.dname");
      }
      java.math.BigInteger biginteger = ax509certificate[0].getSerialNumber();
      String s1 = privatekey.getAlgorithm();
      String s2;
      if(s1.equalsIgnoreCase("DSA"))
        s2 = "SHA1";
      else
        if(s1.equalsIgnoreCase("RSA"))
          s2 = "MD5";
        else
          throw new RuntimeException("private key is not a DSA or RSA key");
      String s3 = (new StringBuilder()).append(s2).append("with").append(s1).toString();
      blockFileName = (new StringBuilder()).append("META-INF/").append(signaturefile.getBaseName()).append(".").append(s1).toString();
      AlgorithmId algorithmid = AlgorithmId.get(s2);
      AlgorithmId algorithmid1 = AlgorithmId.get(s3);
      AlgorithmId algorithmid2 = AlgorithmId.get(s1);
      Signature signature = Signature.getInstance(s3);
      signature.initSign(privatekey);
      ByteArrayOutputStream bytearrayoutputstream = new ByteArrayOutputStream();
      signaturefile.write(bytearrayoutputstream);
      byte abyte0[] = bytearrayoutputstream.toByteArray();
      signature.update(abyte0);
      byte abyte1[] = signature.sign();
      if(contentsigner == null)
        contentsigner = new TimestampedSigner();
      URI uri = null;
      try
      {
        if(s != null)
          uri = new URI(s);
      }
      catch(URISyntaxException urisyntaxexception)
      {
        IOException ioexception = new IOException();
        ioexception.initCause(urisyntaxexception);
        throw ioexception;
      }
      JarSignerParameters jarsignerparameters = new JarSignerParameters(as, uri, x509certificate, abyte1, s3, ax509certificate, abyte0, zipfile);
      block = contentsigner.generateSignedData(jarsignerparameters, flag, s != null || x509certificate != null);
        }
  }
  
  
  public SignatureFile(MessageDigest amessagedigest[], Manifest manifest, ManifestDigester manifestdigester, String s, boolean flag)
  {
    baseName = s;
    String s1 = System.getProperty("java.version");
    String s2 = System.getProperty("java.vendor");
    sf = new Manifest();
    Attributes attributes = sf.getMainAttributes();
    BASE64Encoder base64encoder = new BASE64Encoder();
    attributes.putValue(java.util.jar.Attributes.Name.SIGNATURE_VERSION.toString(), "1.0");
    attributes.putValue("Created-By", (new StringBuilder()).append(s1).append(" (").append(s2).append(")").toString());
    if(flag)
    {
      for(int i = 0; i < amessagedigest.length; i++)
        attributes.putValue((new StringBuilder()).append(amessagedigest[i].getAlgorithm()).append("-Digest-Manifest").toString(), base64encoder.encode(manifestdigester.manifestDigest(amessagedigest[i])));
      
    }
    sun.security.util.ManifestDigester.Entry entry = manifestdigester.get("Manifest-Main-Attributes", false);
    if(entry != null)
    {
      for(int j = 0; j < amessagedigest.length; j++)
        attributes.putValue((new StringBuilder()).append(amessagedigest[j].getAlgorithm()).append("-Digest-").append("Manifest-Main-Attributes").toString(), base64encoder.encode(entry.digest(amessagedigest[j])));
      
    } else
    {
      throw new IllegalStateException("ManifestDigester failed to create Manifest-Main-Attribute entry");
    }
    Map map = sf.getEntries();
    Iterator iterator = manifest.getEntries().entrySet().iterator();
    do
    {
      if(!iterator.hasNext())
        break;
      java.util.Map.Entry entry2 = (java.util.Map.Entry)iterator.next();
      String s3 = (String)entry2.getKey();
      sun.security.util.ManifestDigester.Entry entry1 = manifestdigester.get(s3, false);
      if(entry1 != null)
      {
        Attributes attributes1 = new Attributes();
        for(int k = 0; k < amessagedigest.length; k++)
          attributes1.putValue((new StringBuilder()).append(amessagedigest[k].getAlgorithm()).append("-Digest").toString(), base64encoder.encode(entry1.digest(amessagedigest[k])));
        
        map.put(s3, attributes1);
      }
    } while(true);
  }
  
  public void write(OutputStream outputstream)
  throws IOException
  {
    sf.write(outputstream);
  }
  
  public String getMetaName()
  {
    return (new StringBuilder()).append("META-INF/").append(baseName).append(".SF").toString();
  }
  
  public String getBaseName()
  {
    return baseName;
  }
  
  public Block generateBlock(PrivateKey privatekey, X509Certificate ax509certificate[], boolean flag, String s, X509Certificate x509certificate, ContentSigner contentsigner, String as[], 
      ZipFile zipfile)
  throws NoSuchAlgorithmException, InvalidKeyException, IOException, SignatureException, CertificateException
  {
    return new Block(this, privatekey, ax509certificate, flag, s, x509certificate, contentsigner, as, zipfile);
  }
  
  Manifest sf;
  String baseName;
}
