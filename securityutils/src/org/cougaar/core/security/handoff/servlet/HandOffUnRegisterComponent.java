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


package org.cougaar.core.security.handoff.servlet;

import javax.servlet.Servlet;
import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import java.io.IOException;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;

import org.cougaar.core.blackboard.BlackboardClient;
import org.cougaar.core.mts.MessageAddress;
import org.cougaar.core.security.handoff.blackboard.HandOffUnRegistration;
import org.cougaar.core.security.util.CommunityServiceUtil;
import org.cougaar.core.service.AgentIdentificationService;
import org.cougaar.core.service.BlackboardService;
import org.cougaar.core.service.DomainService;
import org.cougaar.core.service.LoggingService;
import org.cougaar.core.service.community.CommunityService;
import org.cougaar.core.servlet.BaseServletComponent;
import org.cougaar.util.UnaryPredicate;


/**
 * @author rtripathi
 *
 */
public class HandOffUnRegisterComponent extends BaseServletComponent implements BlackboardClient  {
  private MessageAddress agentId;
  private AgentIdentificationService ais;
  private BlackboardService blackboard;
  private LoggingService logging;
  private String path;
  private boolean monitoring;
  private boolean crlMgmtService =true ;

  public void load() {
    super.load();
  }

  protected String getPath() {
    return path;
  }
  public void setParameter(Object o) {
    List l=(List)o;
    path=(String)l.get(0);
  }

  public void setBlackboardService(BlackboardService blackboard) {
    this.blackboard = blackboard;
  }

  public void setAgentIdentificationService( AgentIdentificationService agentis){
    if(agentis!=null) {
      this.ais=agentis;
      agentId = ais.getMessageAddress(); 
    }
  }
  
  public void setLoggingService(LoggingService ls) {
    this.logging=ls;
  }
  
  protected Servlet createServlet() {
    if(ais!=null) {
      agentId = ais.getMessageAddress(); 
    }
    else {
      if(logging.isDebugEnabled()) {
        logging.debug("  createServlet()called  in UnRegisterComponent and ais is null ");
      }
    }
    
    monitoring = (Boolean.valueOf(System.getProperty("org.cougaar.core.security.monitoring","false"))).booleanValue();
    if(logging.isDebugEnabled()) {
      if(monitoring){
        logging.debug("Monitoring is installed ");
      }
      else {
        logging.debug("Monitoring is not installed  ");
      }
    }
    /*
      CrlManagementService crlMgmtService=(CrlManagementService)
      serviceBroker.getService(this, CrlManagementService.class, null);
      if(crlMgmtService==null){
      crlMgmtService =false;
      }
      else {
      crlMgmtService =true;
      }
    */
    crlMgmtService =true;
    return new UnRegisterServlet();
  }

  public void unload() {
    super.unload();
    // FIXME release the rest!
  }

  public void init(ServletConfig config)
    throws ServletException {
    if(logging.isDebugEnabled()) {
      logging.debug("  init(ServletConfig config)called  HandOffUnRegisterComponent");
    }
    ais = (AgentIdentificationService)
      serviceBroker.getService(this, AgentIdentificationService.class, null);
    if(ais!=null) {
      agentId = ais.getMessageAddress();
    }
    else {
      if(logging.isDebugEnabled()) {
        logging.debug("  init() called  in HandOffUnRegisterComponent and ais is null ");
      }
    }
    
  }

  public String getBlackboardClientName() {
    return toString();
  }

  // odd BlackboardClient method:
  public long currentTimeMillis() {
    throw new UnsupportedOperationException(
      this+" asked for the current time???");
  }

  // unused BlackboardClient method:
  public boolean triggerEvent(Object event) {
    // if we had Subscriptions we'd need to implement this.
    //
    // see "ComponentPlugin" for details.
    throw new UnsupportedOperationException(
      this+" only supports Blackboard queries, but received "+
      "a \"trigger\" event: "+event);
  }

  private class UnRegisterServlet extends HttpServlet {

    class UnRegisterServletPredicate implements UnaryPredicate {
      /** @return true if the object "passes" the predicate */
      public boolean execute(Object o) {
        boolean ret = false;
        if (o instanceof HandOffUnRegistration ) {
          return true;
        }
        return ret;
      }
    }


    public void doGet(HttpServletRequest request,
                      HttpServletResponse response) throws IOException {
      response.setContentType("text/html");
      PrintWriter out = response.getWriter();
      String uri = request.getRequestURI();
      // String unregisterUri = uri.substring(0, uri.lastIndexOf('/')) + "/unregister";
      
      out.println("<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0 Transitional//EN\">");
      out.println("<html>");
      out.println("<head>");
      out.println(getJavaScript());
      out.println("<title>MnR DeRegistration Component  </title>");
      out.println("</head>");
      out.println("<body>");
      out.println(createForm(uri));
      out.flush();
    }
    
    public void doPost(HttpServletRequest request,
                       HttpServletResponse response) throws IOException {
      doGet(request,response);
      response.setContentType("text/html");
      String sensor = request.getParameter("Sensor");
      String crl = request.getParameter("CRL");
      String securityCommunity  = request.getParameter("SecurityCommunity");
      String enclave  = request.getParameter("Enclave");
      int sensorcmd=0;
      int crlcmd =0;
      int securitycmd =0;
      PrintWriter out = response.getWriter();
      out.println("<H2>MnR De Registration Started r</H2><BR>");
      out.println("<H3> Monitoring and Response Capabilities De Registration  at agent :"
                  + agentId.toAddress() +" STARTED </H3>");
      try {
        if(sensor!=null){
          sensorcmd= Integer.parseInt(sensor.trim());
          out.println(publishUnregister(sensorcmd,enclave));
        }
        if(crl != null){
          crlcmd= Integer.parseInt(crl.trim());
          out.println(publishUnregister(crlcmd,enclave));
        }
        if(securityCommunity!=null){
          securitycmd= Integer.parseInt(securityCommunity.trim());
          out.println(publishUnregister(securitycmd,enclave));
        }
      }
      catch (NumberFormatException nexp){
        out.println("error "+ nexp.getMessage());
      }
      out.flush();
      
    }
    
    private String publishUnregister(int cmd ,String enclave){
      StringBuffer sb = new StringBuffer();
      try {
        blackboard.openTransaction();
        switch (cmd) {
        case HandOffUnRegistration.UNREGISTER_SENSOR :
          sb.append(" publishUnregister called with sensor ");
          blackboard.publishAdd(new HandOffUnRegistration(HandOffUnRegistration.UNREGISTER_SENSOR));
          break;
          
        case HandOffUnRegistration.UNREGISTER_CRL :
          sb.append(" publishUnregister called with crl  ");
          blackboard.publishAdd(new HandOffUnRegistration(HandOffUnRegistration.UNREGISTER_CRL));
          break ;
          	
        case HandOffUnRegistration.LEAVE_SECURITYCOMMUNITY :
          sb.append(" publishUnregister called with Security Community ");
          List comtype = new ArrayList();
          comtype.add(CommunityServiceUtil.SECURITY_COMMUNITY_TYPE);
          comtype.add(CommunityServiceUtil.MONITORING_SECURITY_COMMUNITY_TYPE);
          blackboard.publishAdd(new HandOffUnRegistration(HandOffUnRegistration.LEAVE_SECURITYCOMMUNITY,comtype));
          break ;
        case HandOffUnRegistration.JOIN__SECURITYCOMMUNITY :	
          sb.append(" publish register called with Security Community "+ enclave);
          if(enclave!=null) {
            blackboard.publishAdd(new HandOffUnRegistration(HandOffUnRegistration.JOIN__SECURITYCOMMUNITY,enclave));
          }
          break;
        default :
          sb.append(" publishUnregister called default ");
          return sb.toString();
          	
        }
      } 
      catch(Exception exp) {
        sb.append("<H3> Exception has occured at  :"  + agentId.toAddress()+ "Messgae :" + exp.getMessage() +"</H3>");
      }
      finally {
        blackboard.closeTransaction();
      }
      try {
        blackboard.openTransaction();
        Collection unregistercol =null;
        unregistercol=blackboard.query(new UnRegisterServletPredicate()); 
        if((unregistercol == null) || (unregistercol.size()<1)){
          sb.append("<H3> Cannot get unregister object  :" + agentId.toAddress()+"</H3>");
          blackboard.closeTransaction();
          return sb.toString();
        }	
        Iterator iter = unregistercol.iterator();
        HandOffUnRegistration ur= null;
        while(iter.hasNext()){
          ur =(HandOffUnRegistration) iter.next();
          sb.append("<H4> Unregister published"+ur.getCommand() +"</H4>");
        }
      }
      catch(Exception exp) {
        sb.append("<H3> Exception has occured at  :"
                  + agentId.toAddress()+ "Messgae :"
                  + exp.getMessage() +"</H3>");
      }
      finally {
        blackboard.closeTransaction();
      }
      return sb.toString();
    }
    
    private String createForm(String uri){
      StringBuffer sb = new StringBuffer();
      sb.append("<form name=\"unregister\" action=\"" +uri + "\" method=\"post\">");
      if(monitoring){
        sb.append("<INPUT TYPE=RADIO NAME=\"Sensor\" VALUE=\"1\" >Unregister Sensor<BR>");
        sb.append("<INPUT TYPE=RADIO NAME=\"Sensor\" VALUE=\"4\">Register Sensor<BR>");
      }
      if(crlMgmtService){
        sb.append("<INPUT TYPE=RADIO NAME=\"CRL\" VALUE=\"2\">Unregister CRL<BR>");
        sb.append("<INPUT TYPE=RADIO NAME=\"CRL\" VALUE=\"5\">Register For CRL<BR>");
      }
      if((monitoring)|| (crlMgmtService)){
        sb.append("<INPUT TYPE=RADIO NAME=\"SecurityCommunity\" VALUE=\"3\">Leave Security Communities<BR>");
        sb.append("<INPUT TYPE=RADIO NAME=\"SecurityCommunity\" VALUE=\"6\">Join Security Communities &nbsp;&nbsp;&nbsp;&nbsp;");
        sb.append("<input TYPE=TEXT NAME=\"Enclave\" SIZE=\"40\" MAXLENGTH=\"40\" <BR>");
        sb.append("<input type=\"submit\" value=\"Submit\" onClick =\"submitme(unregister)\" >");
      }
      else {
        sb.append("<H1> This is a dummy servlet for handoff </H1>");
      }

      return sb.toString();
    }
    
    
    private String getJavaScript(){
      StringBuffer sb= new StringBuffer();
      sb.append("<script language=\"javascript\">"+ "\n");
      sb.append("function submitme(form){" + "\n");
      sb.append("joincommunity = false;" + "\n");
      sb.append("for(i=0;i<myform.elements.length;i++){"+ "\n");
      sb.append("if( myform.elements[i].name == \"SecurityCommunity\" && myform.elements[i].checked  && myform.elements[i].value==6){" +"\n");
      sb.append("alert (\"join community selected \");"+"\n");
      sb.append("joincommunity = true;" + "\n");
      sb.append("if( myform.elements[i].name == \"Enclave\" && myform.elements[i].value== \"\"){" + "\n");
      sb.append("alert (\"Please enter Enclave name \");" + "\n");
      sb.append("return ;" + "\n");
      sb.append("}" + "\n");
      sb.append("form.submit() "+ "\n");
      sb.append("}" + "\n");
      sb.append("</script>");
      return sb.toString();
    }
  }
}
