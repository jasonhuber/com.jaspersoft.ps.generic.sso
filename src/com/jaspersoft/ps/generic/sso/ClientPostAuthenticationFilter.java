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

import com.jaspersoft.jasperserver.api.metadata.user.domain.impl.client.MetadataUserDetails;
import com.jaspersoft.jasperserver.api.metadata.user.service.ProfileAttributeService;

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

		String[][] profileAttributes = clientDetails.getProfileAttributes();
		for (int i= 0; i < profileAttributes.length; i++) {
			//save profile attribute to database
			profileAttributeService.setCurrentUserPreferenceValue(profileAttributes[i][0], profileAttributes[i][1]);
		}
		//reload the profile attributes from the database
		user.setAttributes(profileAttributeService.getProfileAttributesForPrincipal(null, user));
		
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
