package com.jaspersoft.ps.generic.sso;

/**
 * @author aperera@jaspersoft.com, 2013
 * modified: mbielkie@tibco.com, 2015
 * modified: jhuber@tibco.com, 2015
 */


import java.io.IOException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;

import com.jaspersoft.jasperserver.multipleTenancy.MTUserDetails.TenantInfo;

//if we use the JSON stuff below then:
//import net.sf.json.JSONObject;
//import net.sf.json.JSONSerializer;
//a couple jars are also needed....




public class ClientAuthenticationFilter implements InitializingBean, Filter {

	private static Log log = LogFactory.getLog(ClientAuthenticationFilter.class);


	private String validTokenEndpoint = "";
	
	
	public ClientAuthenticationFilter() {
			
	}

	/**
	 * This custom filter is added to the security filter chain to perform user authentication.
	 * The filter first validates the user, then retrieves the user's information.
	 * A ClientDetails user object is then created and set into the session.
	 * Further down the filterChain the JIAuthenticationSynchronizer persists
	 * the user details into the JasperReports Server database.
	 */
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
		//retrieve existing authentication
		Authentication existingAuth = SecurityContextHolder.getContext().getAuthentication();

		HttpServletRequest req = (HttpServletRequest) request;
		HttpSession session = req.getSession();

		String strToken = null;
		//this next line is likely to be "Authorization: Bearer <token>" so we need to parse....
		//I need to send back in the same so I am going to roll with it.
		strToken = req.getHeader("Authorization");
		//need to get the token from the header here.
		//"Authorization: Bearer mytoken123"

		if (strToken == null)
		{
			chain.doFilter(request, response);
			return;
		}

		String sessionToken = (String) session.getAttribute("token");
		if (sessionToken != null && sessionToken.equals(strToken) && existingAuth != null && existingAuth.isAuthenticated()) {
			//already authenticated
			chain.doFilter(request, response);
			return;
		}
		//load user information in a JasperReportsServer user object
		ClientUserDetails userDetails = null;
		try {
			userDetails = getUserDetails(strToken);
		} catch (JSONException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		if (userDetails == null) {
			if (log.isDebugEnabled()) {
				log.debug("user details could not be extracted, proceed with other filters");
			}
			chain.doFilter(request, response);
			return;
		}

		//if an existing authentication is found
		if (existingAuth != null) {
			SecurityContextHolder.getContext().setAuthentication(null);
		}

		//set an authentication token in the session and assign the user details to it
		//(this is used by JIAuthenticationSynchronizer further down the filter chain to persist the user info)
		UsernamePasswordAuthenticationToken authRequest = new UsernamePasswordAuthenticationToken(userDetails, userDetails.getPassword(), userDetails.getAuthorities());
		authRequest.setDetails(userDetails);
		// put this in the current session
		SecurityContextHolder.getContext().setAuthentication(authRequest);

		if (log.isDebugEnabled()) {
			log.debug("authentication object processed");
		}

		//supersede a previous token
		if (sessionToken == null || !sessionToken.equals(strToken)) {
			session.setAttribute("token", strToken);
		}

		//set a flag that will force post-processing of things like profile attributes.
		//SET THIS TO "true" IF YOU ADD PROFILE ATTRIBUTES
		//SET THIS TO "true" IF YOU ADD PROFILE ATTRIBUTES
		request.setAttribute("clientAuth", "true");

		//continue with filter chain
		chain.doFilter(req, response);
	}


	/**
	 * Validates session token and retrieves all user details
	 * @throws JSONException 
	 */
	@SuppressWarnings("unchecked")
	private ClientUserDetails getUserDetails(String token) throws JSONException {
	//alternative JSON processor:
		log.debug("begin token validation program");

		log.debug("received token info : " + token);

	
		JSONObject json = util.GetJSONfromURL(token, validTokenEndpoint);
			log.debug("JSON Parsed");

		String auth_id = json.getString("Username");

		//roles
		List<GrantedAuthority> authorities = new ArrayList<GrantedAuthority>();
		JSONArray roles = json.getJSONArray("Roles"); 
		//authorities.add(new SimpleGrantedAuthority("ROLE_USER"));
		for (int i = 0; i < roles.length(); i++) {
			authorities.add(new SimpleGrantedAuthority(roles.getString(i)));
		}
		
		//profile attributes
		Iterator<String> iter = json.getJSONObject("Attributes").keys();
		List<String[]> attributesAttr = new ArrayList<String[]>();

		while(iter.hasNext())
		{
			String key = iter.next();
			String value = json.getString(key);
			attributesAttr.add(new String[]{key, value});
		}

		String[][] attributes = new String[attributesAttr.size()][2];
			Iterator<String[]> attributesIter = attributesAttr.iterator();
		for (int i = 0; attributesIter.hasNext(); i++) {
			attributes[i] = attributesIter.next();
		}

		//organization
		List<TenantInfo> tenants = new ArrayList<TenantInfo>();
		ClientTenantInfo tenant = new ClientTenantInfo(json.getString("CurrentOperationId"), json.getString("CurrentOperationName"), json.getString("CurrentOperationName"));
		
		tenants.add(tenant);


		ClientUserDetails userDetails = new ClientUserDetails(auth_id, authorities, attributes, tenants);
		return userDetails;

	}

	/**
	 * This is the validation that the request contains all needed information.
	 * Don't add too much functionality here as this is checked for all
	 * requests.
	 *
	 * @param req
	 * @return <code>true</code> if enough information found, otherwise false.
	 */

	
	
	// -- helper methods
	@Override
	public void afterPropertiesSet() throws Exception {

	}

	@Override
	public void destroy() {

	}

	@Override
	public void init(FilterConfig arg0) throws ServletException {

	}


	public String getvalidTokenEndpoint() {
		return validTokenEndpoint;
	}

	public void setvalidTokenEndpoint(String validTokenEndpoint) {
		this.validTokenEndpoint = validTokenEndpoint;
	}

}