package com.jaspersoft.ps.generic.sso;

/**
 * @author aperera@jaspersoft.com, 2013
 * modified: mbielkie@tibco.com, 2015
 * modified: jhuber@tibco.com, 2015
 */


import java.io.IOException;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;
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
import org.springframework.beans.factory.InitializingBean;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;


//if we use the JSON stuff below then:
//import net.sf.json.JSONObject;
//import net.sf.json.JSONSerializer;
//a couple jars are also needed....


import com.jaspersoft.jasperserver.multipleTenancy.MTUserDetails.TenantInfo;


public class ClientAuthenticationFilter implements InitializingBean, Filter {

	private static int MINUTE_OFFSET = -2;
	private static final String DATETIME_FORMAT = "MM/dd/yyyy hh:mm:ss a XXX";

	private static Log log = LogFactory.getLog(ClientAuthenticationFilter.class);

	private String authToken;
	private String currentToken;

	private String tokenSessionAttribute ="clientAuthToken";

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

		//if no token is found proceed with other filters
		if (!isClientRequest(request)) {
			if (log.isDebugEnabled()) {
				log.debug("this is not a custom auth request, proceed with other filters");
			}
			chain.doFilter(request, response);
			return;
		}
		
		//retrieve existing authentication
		Authentication existingAuth = SecurityContextHolder.getContext().getAuthentication();

		HttpServletRequest req = (HttpServletRequest) request;
		HttpSession session = req.getSession();
		String sessionToken = (String) session.getAttribute(tokenSessionAttribute);
		if (sessionToken != null && sessionToken.equals(currentToken) && existingAuth != null && existingAuth.isAuthenticated()) {
			//already authenticated
			chain.doFilter(request, response);
			return;
		}

		//load user information in a JasperReportsServer user object
		ClientUserDetails userDetails = getUserDetails(req);

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
		if (sessionToken == null || !sessionToken.equals(currentToken)) {
			session.setAttribute(tokenSessionAttribute, currentToken);
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
	 */
	private ClientUserDetails getUserDetails(ServletRequest req) {
		try {
	
			//get user info
			//String username = getUsernameFromToken(currentToken);
			String username = "Jason";
		
			List<TenantInfo> tenants = new ArrayList<TenantInfo>();
			ClientTenantInfo tenant = new ClientTenantInfo("jasonorg", "JasonOrg", null);
			tenants.add(tenant);

			//roles
			List<GrantedAuthority> authorities = new ArrayList<GrantedAuthority>();
			authorities.add(new SimpleGrantedAuthority("ROLE_JASON"));
				
			String[][] attributes = new String[1][2];
			attributes[0][0] ="Campus";
			attributes[0][1] ="ASU";
			
			
			ClientUserDetails userDetails = new ClientUserDetails(username, tenants, authorities, attributes);
			return userDetails;

		} catch (Exception e){
			log.error("Error retrieving SSO user info", e);
			return null;
		}
		
		/*
		 * alternative JSON processor:
		 * log.debug("begin token validation program");   

		String token = getToken(req);

		log.debug("received token info : " + token);

		HttpURLConnection conn = null;

		//get user info for the user, including roles and attributes (this is using POST)
		String userInfoStr = null;

		try {
			String urlStr = validTokenEndpoint + token;
	
			log.debug("constructed URL String : " + urlStr);
	
			URL url = new URL(urlStr);
	
			log.debug("before Open connection : ");
			
			conn = (HttpURLConnection) url.openConnection();
			conn.setRequestMethod("GET");
			conn.setDoOutput(true); //this is for POST and PUT
			conn.setDoInput(true); //this is for GET
			conn.setUseCaches(false);
			conn.setAllowUserInteraction(false);
			
			log.debug("before response check : ");
	
			String userpass = URI_user + ":" + URI_pass;
			String basicAuth = "Basic " + javax.xml.bind.DatatypeConverter.printBase64Binary(userpass.getBytes());
			conn.setRequestProperty("Authorization", basicAuth);
			
			if (conn.getResponseCode() != 200) 
				return null;
	
			log.debug("got the response back : " + conn.getResponseCode());
	
			//Get Response
			InputStream is = conn.getInputStream();
	
			userInfoStr = convertInputStream2String(is);
	
			log.info("Successfully made JSON call, results: " + userInfoStr);
		} catch (Exception e) {
			log.error("Failed retrieving user info", e);
		} finally {
			if(conn != null) {
				conn.disconnect(); 
			}
		}
	
		log.debug("Starting to parse JSON");
		JSONObject json = new JSONObject();
		try
		{
			json = (JSONObject) JSONSerializer.toJSON(userInfoStr);	
		}
		catch(Exception e) {
			log.error("JSON Was invalid. Info Received: " + userInfoStr, e);
		} 
		
		log.debug("JSON Parsed");

		String auth_id = json.getString("username");

		//roles
		//Currently hardcoding to just include ROLE_USER. You will need to add
		//to this section if more roles are desired and/or synced from external system.
		List<GrantedAuthority> authorities = new ArrayList<GrantedAuthority>();
		authorities.add(new SimpleGrantedAuthority("ROLE_USER"));

		//profile attributes
		@SuppressWarnings("unchecked")
		Iterator<String> iter = json.keys();
		List<String[]> attributesAttr = new ArrayList<String[]>();
		
		//For each entry in attributeMap (specified in xml file), get the "key" 
		//value from the JSON object and set it into our attributes as the new "value"
		//
		//i.e. if you have <entry key="amp_user_sid" value="sid"/> defined in the xml, 
		//the value for "sid" will be stored into Jaspersoft attribute as "user_sid"
		for (Map.Entry<String, String> entry : attributeMap.entrySet())
		{
			try 
			{
				attributesAttr.add(new String[]{entry.getValue(), json.getString(entry.getKey())});
			}
			catch (net.sf.json.JSONException je)
			{
				log.error("Key specified in XML file for mapping (" + entry.getKey() + ") does not exist in JSON response object, skipping");
			}
		}		
		
		List<String> excludedAttributesList = Arrays.asList(excludeAttributes.split("\\s*,\\s*"));
		while(iter.hasNext())
		{
			String key = iter.next();
			if (excludedAttributesList.contains(key))
				continue;
			String value = json.getString(key);
			attributesAttr.add(new String[]{key, value});
		}

		String[][] attributes = new String[attributesAttr.size()][2];
			Iterator<String[]> attributesIter = attributesAttr.iterator();
		for (int i = 0; attributesIter.hasNext(); i++) {
			attributes[i] = attributesIter.next();
		}

		//organizations
		//No need to process organizations until there are more than one. 
		//When creating the ClientUserDetails object, not passing tenants
		//will force everyone into the base organization (organization_1)
		//Uncomment section below and create a 'tenant' for the org the 
		//user should be part of (multiples needed if suborgs are used)
		
		
		List<TenantInfo> tenants = new ArrayList<TenantInfo>();
		ClientTenantInfo tenant = new ClientTenantInfo(org_name, org_id, null);
		tenants.add(tenant); 
		 
		
		ClientUserDetails userDetails = new ClientUserDetails(auth_id, authorities, attributes);
end: alternate JSON*/
		
	}

	/**
	 * @param strDatetime
	 * @throws ParseException
	 */
	public boolean isTimestampValid(String strDatetime) throws ParseException {
		SimpleDateFormat myFormatter = new SimpleDateFormat(DATETIME_FORMAT);
		Date tokenDate = myFormatter.parse(strDatetime);
		
		Calendar cal = Calendar.getInstance();
		//the minute offset is a negative number
		//if it isn't, I will make it so:
		if(MINUTE_OFFSET > 0)
		{
			MINUTE_OFFSET *= -1;
		}
		//this will get our farthest time back:
		cal.add(Calendar.MINUTE, MINUTE_OFFSET);
		Date twoMinutesAgoDate = cal.getTime();
		
		//this will get our farthest time in the future:
		cal.add(Calendar.MINUTE, (MINUTE_OFFSET * -1)*2);
		Date twoMinutesIntoTheFuture = cal.getTime();
				
		if (tokenDate.compareTo(twoMinutesAgoDate) < 0 || tokenDate.compareTo(twoMinutesIntoTheFuture) > 0)
		{
			if (log.isDebugEnabled())
			{
				log.warn("Token datetime is more than " + MINUTE_OFFSET + " minutes ago, failing login");
			}
			return false;
		}
		
		return true;
	}


	
	/**
	 * This is the validation that the request contains all needed information.
	 * Don't add too much functionality here as this is checked for all
	 * requests.
	 * 
	 * @param req
	 * @return <code>true</code> if enough information found, otherwise false.
	 */
	private boolean isClientRequest(ServletRequest req) {
		String aToken = req.getParameter(authToken);
		return (aToken != null) && !aToken.trim().equals("");
	}



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

	public String getAuthToken() {
		return authToken;
	}

	public void setAuthToken(String authToken) {
		this.authToken = authToken;
	}

}