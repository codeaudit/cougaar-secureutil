
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

package org.cougaar.core.security.handoff.plugin;

import java.util.Enumeration;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.mts.MessageAddress;
import org.cougaar.core.plugin.ComponentPlugin;
import org.cougaar.core.blackboard.IncrementalSubscription;

import org.cougaar.core.service.DomainService;
import org.cougaar.core.service.BlackboardService;
import org.cougaar.core.service.LoggingService;
import org.cougaar.core.service.SchedulerService;
import org.cougaar.core.service.ThreadService;
import org.cougaar.core.thread.Schedulable;

import org.cougaar.core.service.community.Community;
import org.cougaar.core.service.community.CommunityChangeEvent;
import org.cougaar.core.service.community.CommunityChangeListener;
import org.cougaar.core.service.community.CommunityService;
import org.cougaar.core.service.community.CommunityResponse;
import org.cougaar.core.service.community.CommunityResponseListener;
import org.cougaar.util.UnaryPredicate;

import org.cougaar.core.security.handoff.blackboard.HandOffUnRegistration;
import org.cougaar.core.security.util.CommunityServiceUtil;
import org.cougaar.core.security.util.CommunityServiceUtilListener;


import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.BasicAttribute;
import javax.naming.directory.BasicAttributes;


/**
 * @author rtripathi
 *
 */

class LeaveCommunityPredicate implements UnaryPredicate{
  public boolean execute(Object o) {
    boolean ret = false;
    HandOffUnRegistration unregister= null;
    if (o instanceof HandOffUnRegistration ) {
      unregister =(HandOffUnRegistration)o;
      int command = unregister.getCommand();
      if((command == HandOffUnRegistration.LEAVE_SECURITYCOMMUNITY)){
        return true;
      }
    }
    return ret;
  }
}
class JoinCommunityPredicate implements UnaryPredicate{
  public boolean execute(Object o) {
    boolean ret = false;
    HandOffUnRegistration unregister= null;
    if (o instanceof HandOffUnRegistration ) {
      unregister =(HandOffUnRegistration)o;
      int command = unregister.getCommand();
      if(command == HandOffUnRegistration.JOIN__SECURITYCOMMUNITY){
        return true;
      }
    }
    return ret;
  }
}

public class CommunityMembershipChangerPlugin extends ComponentPlugin {
  
  protected CommunityService _cs;	
  protected DomainService _domainService;
  protected LoggingService _log;
  
  private MessageAddress myAddress;
  private IncrementalSubscription leaveCommunity;
  private IncrementalSubscription joinCommunity;
  private CommunityServiceUtil _csu;
  private boolean monitoringcommunitychange =false;
  private boolean securitycommunitychange =false;
  private  CommunityChangeListener _ccl;
  
  public void setDomainService(DomainService aDomainService) {
    _domainService = aDomainService;
    _log = (LoggingService) getServiceBroker().
      getService(this, LoggingService.class, null);
  }
  
  /**
   * Used by the binding utility through reflection to get my DomainService
   */
  public DomainService getDomainService() {
    return _domainService;
  }
  
  
  public void setCommunityService(CommunityService cs) {
    //System.out.println(" set community services Servlet component :");
    this._cs=cs;
  }
  public CommunityService getCommunityService() {
    return this._cs;
  }
  
  protected void setupSubscriptions() {
    
    ServiceBroker sb = getBindingSite().getServiceBroker();
    if(_log == null) {
      _log = (LoggingService)sb.getService(this, LoggingService.class, null);
    }
    myAddress = getAgentIdentifier();
    _csu = new CommunityServiceUtil(sb);
    leaveCommunity=(IncrementalSubscription)getBlackboardService().subscribe(new LeaveCommunityPredicate());
    joinCommunity = (IncrementalSubscription)getBlackboardService().subscribe(new JoinCommunityPredicate());

    
  }
  
  /* (non-Javadoc)
   * @see org.cougaar.core.plugin.ComponentPlugin#execute()
   */
  protected void execute() {
    
    if(leaveCommunity.hasChanged()){
      Enumeration enumCommunityleave= leaveCommunity.getAddedList();
      if(enumCommunityleave != null){
        if(enumCommunityleave.hasMoreElements()){
          leaveCommunity(enumCommunityleave);
        }
      }
    }
    if(joinCommunity.hasChanged()){
      Enumeration enumCommunityjoin= joinCommunity.getAddedList();
      if(_log.isDebugEnabled()){
        _log.debug("join community subscription has changes ");
      }
      if(enumCommunityjoin != null){
        if(enumCommunityjoin.hasMoreElements()){
          if(_log.isDebugEnabled()){
            _log.debug("Join communit is called ");
          }
          joinCommunity(enumCommunityjoin);
        }
      }
    }
    
    
  }
  
  public void publishRegisterSensor(){
    HandOffUnRegistration register =  new HandOffUnRegistration(HandOffUnRegistration.REREGISTER_SENSOR);
    publishReregister(register);
    monitoringcommunitychange =true;
    removeCommunityChnageListener();
    
  }
  
  public void publishReregister(final HandOffUnRegistration register){
    ServiceBroker sb =getBindingSite().getServiceBroker();
    ThreadService threadService = (ThreadService)sb.getService(this, ThreadService.class, null);
    final BlackboardService bbs = getBlackboardService();
    Schedulable publisherThread = threadService.getThread(CommunityMembershipChangerPlugin.this, new Runnable( ) {
        public void run(){
          try {
            bbs.openTransaction();
            bbs.publishAdd(register);
            if(_log.isDebugEnabled()){
              _log.debug("Reregistration object  "+ register.getCommand());
            }
          }
          catch(Exception exp) {
            if(_log.isDebugEnabled()){
              _log.debug("Cannot publish crl reregistration "+ exp.getMessage());
            }
          }
          finally {
            bbs.closeTransaction();
          }
        }}, "reregisterThread");
    publisherThread.start();
  }
  public void publishRegisterCrl(){
    HandOffUnRegistration register = new HandOffUnRegistration(HandOffUnRegistration.REREGISTER_CRL);
    publishReregister(register);
    securitycommunitychange =true;
    removeCommunityChnageListener();
  }

  public void removeCommunityChnageListener(){
    if((_ccl!=null)&& (monitoringcommunitychange) &&  (securitycommunitychange)){
      _cs.removeListener(_ccl);
      monitoringcommunitychange =false;
      securitycommunitychange =false;
    }
  }
  
  private void leaveCommunity( Enumeration communityleaveRequest){
    HandOffUnRegistration unregister = null;
    while (communityleaveRequest.hasMoreElements()){
      unregister = (HandOffUnRegistration)communityleaveRequest.nextElement();
      List communitieslist = 	unregister.getCommunityTypes();
      if(communitieslist!=null){
        Iterator iter = communitieslist.iterator();
        String communitytype =null;
        while(iter.hasNext()){
          communitytype= (String)iter.next();
          final String commtype=  communitytype;
          final CommunityServiceUtilListener csu = new CommunityServiceUtilListener() {
              public void getResponse(Set resp) {
                if(_log.isDebugEnabled()){
                  _log.debug(" call back for community is called :" + resp );
                }
                if((resp!=null)&& (!resp.isEmpty())){
                  Iterator respiter = resp.iterator();
                  while(respiter.hasNext()){
                    Community community = (Community)respiter.next(); 
                    String comName= community.getName();
                    _cs.leaveCommunity(comName,myAddress.toString(),
                                       new UnRegisterCommunityResponseListener(commtype,myAddress.toString()));
                  }
                }
              }
            };
          _csu.getSecurityCommunities(communitytype,csu);
        }
      }
    }
    
  }
  
  private void joinCommunity( Enumeration communityjoinRequest){
    HandOffUnRegistration unregister = null;
    while (communityjoinRequest.hasMoreElements()){
      unregister = (HandOffUnRegistration)communityjoinRequest.nextElement();
      if(_log.isDebugEnabled()){
        _log.debug(" join community called with "+ unregister.toString());
      }
      String enclave = unregister.getEnclaveName();
      String mnrcommunity = enclave+ "-MnR-SECURITY-COMM";
      String securitycommunity = enclave+ "-SECURITY-COMM";
      Attribute attr = new BasicAttribute("Role","Member");
      Attribute attr1 = new BasicAttribute("EntityType","Agent");
      Attributes attrs= new BasicAttributes();
      attrs.put(attr);
      attrs.put(attr1);
      _cs.joinCommunity(mnrcommunity, myAddress.toString(),CommunityService.AGENT,attrs,false,null,
                        new RegisterCommunityResponseListener(mnrcommunity,myAddress.toString()));
      _cs.joinCommunity(securitycommunity, myAddress.toString(),CommunityService.AGENT,attrs,false,null,
                        new RegisterCommunityResponseListener(securitycommunity,myAddress.toString()));
      _ccl=  new HandOffCommunityChange();
      _cs.addListener(_ccl);
    }
    
  }
 
  private class RegisterCommunityResponseListener implements CommunityResponseListener {
    private String communityName;
    private String agent;
    
    public RegisterCommunityResponseListener(String communitname, String myagent){
      communityName= communitname;
      agent = myagent;
    }

    public void getResponse( CommunityResponse response ) {
      if (response.getStatus() == CommunityResponse.SUCCESS) {
        if (_log.isDebugEnabled()){
          _log.debug("Successfully  Joined community."+ "Agent "+ agent + "CommunityName "+ communityName);
        }
      }
      else {
        if (_log.isDebugEnabled()){
          _log.debug("Unable to process community Join request: " + response.getStatusAsString() + "Agent "+ agent 
                     + "CommunityName "+ communityName); 
        }
      }
    }
  }
  
  private class UnRegisterCommunityResponseListener implements CommunityResponseListener {
    private String communityType;
    private String agent;
    
    public UnRegisterCommunityResponseListener(String communittype, String myagent){
      communityType= communittype;
      agent = myagent;
    }
    
    public void getResponse(CommunityResponse response) {
      if (response.getStatus() == CommunityResponse.SUCCESS) {
        if (_log.isDebugEnabled()){
          _log.debug("Successfully leave community."+ "Agent "+ agent + "CommunityType "+ communityType);
        }
      }
      else {
        if (_log.isDebugEnabled()){
          _log.debug("Unable to process community leave request: " + response.getStatusAsString() + "Agent "+ agent 
                     + "CommunityType "+ communityType); 
        }
      }
    }
    
  
  }
  
  private class HandOffCommunityChange implements CommunityChangeListener {
    
    public void communityChanged( CommunityChangeEvent event) {
      if (event.getType() == CommunityChangeEvent.ADD_ENTITY) {
        if (_log.isDebugEnabled()) {
          _log.debug("Community change report -->"+ event.getWhatChanged());
        }
        if( event.getWhatChanged().equals(myAddress.toString())){
          Community community = event.getCommunity();
          if (CommunityServiceUtil.isCommunityType(community, CommunityServiceUtil.MONITORING_SECURITY_COMMUNITY_TYPE)) {
            if (_log.isDebugEnabled()) {
              _log.debug("Agent "+myAddress.toString()+" " +community.getName() + " is of type "
                         +CommunityServiceUtil.MONITORING_SECURITY_COMMUNITY_TYPE);
              _log.debug("Calling reregister sensor ");
            }
            publishRegisterSensor();
          }
          if(CommunityServiceUtil.isCommunityType(community, CommunityServiceUtil.SECURITY_COMMUNITY_TYPE)){
            if (_log.isDebugEnabled()) {
              _log.debug("Agent "+myAddress.toString()+" " +community.getName() + " is of type " 
                         +CommunityServiceUtil.MONITORING_SECURITY_COMMUNITY_TYPE);
              _log.debug("Calling reregister CRL ");
            }
            publishRegisterCrl();
          }
        }
        else {
          if (_log.isDebugEnabled()) {
            _log.debug("Got Add Entity but it is for some other agent -->"+ event.getWhatChanged());
          }
        }
            
      }
    }

    /* (non-Javadoc)
     * @see org.cougaar.core.service.community.CommunityChangeListener#getCommunityName()
     */
    public String getCommunityName() {
      // TODO Auto-generated method stub
      return null;
    }   
 
  }
  
}
