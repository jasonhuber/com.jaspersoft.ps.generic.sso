package com.jaspersoft.ps.generic.sso;
/**
 * @author aperera@jaspersoft.com, 2013
 * modified: mbielkie@tibco.com, 2015
 * modified: jhuber@tibco.com, 2015
 */


import java.io.IOException;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.Assert;

import com.jaspersoft.jasperserver.api.metadata.common.service.RepositoryService;
import com.jaspersoft.jasperserver.api.metadata.user.domain.ProfileAttribute;
import com.jaspersoft.jasperserver.api.metadata.user.domain.impl.client.MetadataUserDetails;
import com.jaspersoft.jasperserver.api.metadata.user.service.ObjectPermissionService;
import com.jaspersoft.jasperserver.api.metadata.user.service.ProfileAttributeCategory;
import com.jaspersoft.jasperserver.api.metadata.user.service.ProfileAttributeService;
import com.jaspersoft.jasperserver.api.metadata.user.service.TenantService;
import com.jaspersoft.jasperserver.api.metadata.user.service.UserAuthorityService;
import com.jaspersoft.jasperserver.api.security.externalAuth.processors.AbstractExternalUserProcessor;

public class ClientPostAuthenticationFilter implements InitializingBean, Filter {

	private static Log log = LogFactory.getLog(ClientPostAuthenticationFilter.class);

	private ProfileAttributeService profileAttributeService;


	/**
	 * this filter will be executed after the JIAuthenticationSynchronizer.
	 * a new user details object will exist in the session, which can be used to persist profile attributes.
	 * this filter will only execute if the clientAuth parameter is found in the request, to prevent execution on every request.
	 */
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {

		//process only if this is a client authentication
		Object clientAuth = request.getAttribute("clientAuth");
		if ((clientAuth == null) || !"true".equals(clientAuth)) {
			chain.doFilter(request, response);
			return;
		}

		//get the authentication object from the security context
		Authentication auth = SecurityContextHolder.getContext().getAuthentication();

		//the authentication synchronizer creates a new MetadataUserDetails object which holds all user information
		MetadataUserDetails user = (MetadataUserDetails) auth.getPrincipal();

		//retrieve the original user details
		ClientUserDetails clientDetails = (ClientUserDetails) user.getOriginalAuthentication().getPrincipal();

		//this should never happen
		if (clientDetails == null) {
			if (log.isWarnEnabled()) {
				log.warn("client auth header token is found, but no client userdetails");
			}
			chain.doFilter(request, response);
			return;
		}

		
		//this was changed in 6.1.1, so we updated it:
		String[][] profileAttributes = clientDetails.getProfileAttributes();
		for (int i= 0; i < profileAttributes.length; i++) {
			//save profile attribute to database
			ProfileAttribute myAttr = profileAttributeService.newProfileAttribute(null);
			myAttr.setPrincipal(user);
			myAttr.setAttrName(profileAttributes[i][0]);
			myAttr.setAttrValue(profileAttributes[i][1]);
			log.debug("Profile attribute " + i + ": " + profileAttributes[i][0] + "-" + profileAttributes[i][1]);
			try
			{
				profileAttributeService.putProfileAttribute(null, myAttr);
			}
			catch (Exception e)
			{
				log.error("Exception caught trying to save profile attribute to repository: " + e.toString());	
			}
		}
		
		//set the attributes back on the user object so they are available to current session
		user.setAttributes(profileAttributeService.getCurrentUserProfileAttributes(null, ProfileAttributeCategory.TENANT));
		
		//proceed with other filters
		chain.doFilter(request, response);
	}

	// -- helper methods

	@Override
	public void afterPropertiesSet() throws Exception {
		Assert.notNull(profileAttributeService);
		//Assert.notNull(profileAttrName);
	}

	@Override
	public void destroy() {

	}

	@Override
	public void init(FilterConfig arg0) throws ServletException {
	
	}

	// getter and setter methods for bean properties

	public ProfileAttributeService getProfileAttributeService() {
		return profileAttributeService;
	}

	public void setProfileAttributeService(ProfileAttributeService profileAttrService) {
		profileAttributeService = profileAttrService;
	}
}
