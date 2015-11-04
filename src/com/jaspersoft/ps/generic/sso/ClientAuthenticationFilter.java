package com.jaspersoft.ps.generic.sso;

/**
 * @author aperera@jaspersoft.com, 2013
 * modified: mbielkie@tibco.com, 2015
 * modified: jhuber@tibco.com, 2015
 */


import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
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

import org.apache.commons.lang.exception.ExceptionUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.StringUtils;


import com.jaspersoft.jasperserver.multipleTenancy.MTUserDetails.TenantInfo;


public class ClientAuthenticationFilter implements InitializingBean, Filter {

	private static int MINUTE_OFFSET = -2;
	private static final String DATETIME_FORMAT = "MM/dd/yyyy hh:mm:ss a XXX";
	private static String ORG_IDENTIFIER = "orgId=";
	private static String ROLE_IDENTIFIER = "roles=";
	private static String USER_IDENTIFIER = "username=";
	private static String DATE_IDENTIFIER = "datetime=";
	private static String ORG_SEPARATOR = "/";
	private static String ROLE_SEPARATOR = "%";
	private static String TOKEN_SEPARATOR = "|";

	private static Log log = LogFactory.getLog(ClientAuthenticationFilter.class);

	private String authToken;
	private String currentToken;

	private String tokenSessionAttribute ="clientAuthToken";

	/**
	 * The security xml file (applicationContext-security-web.xml or similar) will
	 * define this bean and needs to have lines such as the following to pass in the
	 * url information:
	 * 
	 * <constructor-arg name="orgIdentifier" value="orgId" />
	 * <constructor-arg name="roleIdentifier" value="roles" />
	 * <constructor-arg name="userIdentifier" value="username" />
	 * <constructor-arg name="datetimeIdentifier" value="datetime" />
	 * <constructor-arg name="orgSeparator" value="/" />
	 * <constructor-arg name="roleSeparator" value="%" />
	 * <constructor-arg name="tokenSeparator" value="|" />
	 * <constructor-arg name="timeOffset" type="int" value="-2" />
	 * 
	 * @param orgIdentifier
	 * @param roleIdentifier
	 * @param userIdentifier
	 * @param datetimeIdentifier
	 * @param orgSeparator
	 * @param roleSeparator
	 * @param tokenSeparator
	 * @param timeOffset
	 */
	public ClientAuthenticationFilter(String orgIdentifier, String roleIdentifier, String userIdentifier, String datetimeIdentifier, String orgSeparator, String roleSeparator, String tokenSeparator, int timeOffset) {
		ORG_IDENTIFIER = orgIdentifier.concat("=");
		ROLE_IDENTIFIER = roleIdentifier.concat("=");
		USER_IDENTIFIER = userIdentifier.concat("=");
		DATE_IDENTIFIER = datetimeIdentifier.concat("=");
		ORG_SEPARATOR = orgSeparator;
		ROLE_SEPARATOR = roleSeparator;
		TOKEN_SEPARATOR = tokenSeparator;
		MINUTE_OFFSET = timeOffset;
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

		String strToken = getToken(request);
		
		String decryptedToken = decryptToken(strToken);
		if (decryptedToken == null)
		{
			chain.doFilter(request, response);
			return;
		}
		
		currentToken = decodeToken(decryptedToken);
		if (currentToken == null)
		{
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
		request.setAttribute("clientAuth", "false");

		//continue with filter chain
		chain.doFilter(req, response);
	}


	/**
	 * Decrypts the provided token utilizing the Rfc2898Decryptor 
	 * 
	 * @param thisToken
	 * @return String The decrypted token
	 */
	private String decryptToken(String thisToken) {
	//TODO: implement this if needed
		return thisToken;
	}


	/**
	 * Decodes the provided string (using URLDecoder)
	 * 
	 * @param encodedToken
	 * @return String The decoded string
	 */
	private String decodeToken(String encodedToken) {
		try {
			String decodedToken = URLDecoder.decode(encodedToken.replace("+", "%2B"), "UTF-8");
			return decodedToken;
		
		} catch (UnsupportedEncodingException e) {
			log.error("Exception trying to decode URL: " + ExceptionUtils.getStackTrace(e));
			return null;
		}
	}


	/**
	 * Validates session token and retrieves all user details
	 */
	private ClientUserDetails getUserDetails(ServletRequest req) {
		try {
			//get datetime timestamp
			String strDatetime = getDatetimeFromToken(currentToken);
			if (!isTimestampValid(strDatetime))
			{
				return null;
			}

			//get user info
			String username = getUsernameFromToken(currentToken);
			//if no user credentials, return null
			if (username == null) {
				if (log.isDebugEnabled()) {
					log.debug("No username provided.");
				}
				return null;
			}
			
			//get org info
			List<TenantInfo> tenants = getOrganizations(currentToken);

			if (log.isDebugEnabled()) {
				log.debug("Successfully retrieved ORGANIZATION (client) data:\n");
				log.debug("tenant list = " + tenants + "\n");
			}

			//roles
			List<GrantedAuthority> authorities = new ArrayList<GrantedAuthority>();
			String roles = getRolesFromToken(currentToken);
			if (!roles.contains(ROLE_SEPARATOR))
			{
				authorities.add(new SimpleGrantedAuthority(roles));
				log.debug("Only one role passed: " + roles);
			}
			else
			{
				String[] strArrayRoles = roles.split(ROLE_SEPARATOR);
				for (int i=0; i<strArrayRoles.length; i++) {
					String currentRole = strArrayRoles[i];
					authorities.add(new SimpleGrantedAuthority(currentRole));
					log.debug("Multiple Roles passed, Role #" + i + ": " + currentRole);
				} 				
			}

			//Hard coding all users to have only ROLE_USER
			//Modify this if roles should expand in the future and you want SSO code to take care of this
//			GrantedAuthority[] authorities = new GrantedAuthority[1];
//			authorities[0] = new GrantedAuthorityImpl("ROLE_USER");
			
			//get profile attributes
			//Uncomment below section to grab attributes (clientAccessList) again and change the null paramater to attributes in call below this section
			//Also make sure to re-add the post auth bean/filter to the security xml file
			
//			String attributesQuery = "select client_id from ag2.sec_user_clients where sec_usr_id = ? "
//					+ "union "
//					+ "select client_id from ag2.sec_user_clients where sec_grp_id in "
//					+ "(select sec_grp_id from ag2.sec_grp_mbrs where sec_usr_id = ?)";
//
//			ps = conn.prepareStatement(attributesQuery);
//			ps.setLong(1, secUsrID);
//			ps.setLong(2, secUsrID);
//			rs = ps.executeQuery();
//			List<String[]> attributeList = new ArrayList<String[]>();
//			String accessibleClientIDList = "";
//			
//			while (rs.next()) {
//				accessibleClientIDList = accessibleClientIDList.concat(rs.getString(1) + ",");
//			}
//			accessibleClientIDList = accessibleClientIDList.substring(0, accessibleClientIDList.lastIndexOf(","));
//			attributeList.add(new String[]{"accessClients", accessibleClientIDList});
//			rs.close();
//			ps.close();
//
//			if (log.isDebugEnabled()) {
//				log.debug("Successfully retrieved PROFILE ATTRIBUTE data:\n");
//				log.debug("accessibleClientIDList = " + accessibleClientIDList + "\n");
//			}
//
//			String[][] attributes = new String[attributeList.size()][];
//			Iterator<String[]> attributesIter = attributeList.iterator();
//			for (int i = 0; i < attributes.length; i++) {
//				attributes[i] = attributesIter.next();
//			}

			ClientUserDetails userDetails = new ClientUserDetails(username, tenants, authorities, null);
			return userDetails;

		} catch (Exception e){
			log.error("Error retrieving SSO user info", e);
			return null;
		}
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
	 * Retrieves a list of TenantInfo objects. These are the organizations that are in
	 * the supplied token. Can be one or many - if more than one is found, multiple
	 * tenants will be created and they will have an ORG->SUB-ORG relationship.
	 * 
	 * @return List<TenantInfo> The List of organizations
	 */
	private List<TenantInfo> getOrganizations(String thisToken) {
		//get org info
		List<TenantInfo> tenants = new ArrayList<TenantInfo>();
		String orgId = null;
//		String orgName = null;

		
		String orgIdList = getOrgsFromToken(thisToken);
		//String orgNameList = rs.getString(3);
		int pathLen = StringUtils.countOccurrencesOf(orgIdList, ORG_SEPARATOR) + 1;
		int slashLocation = 0;
		//int pipeLocation = 0;
		
		ClientTenantInfo tenant = null;
		if (pathLen == 1)
		{
			//orgId = orgIdList.substring(0);
			//orgName = orgNameList.substring(1);
//			tenant = new ClientTenantInfo(orgId, orgName, null);
			tenant = new ClientTenantInfo(orgIdList, orgIdList, null);
			tenants.add(tenant);
		}
		else if (pathLen > 1)
		{
			for (int i=0; i<pathLen; i++)
			{
				slashLocation = orgIdList.indexOf(ORG_SEPARATOR);
				if (log.isDebugEnabled())
				{
					log.debug("orgIdList: " + orgIdList);
					log.debug("slashlocation: " + slashLocation);
				}
				//pipeLocation = orgNameList.indexOf("|", 1);
				if (slashLocation > -1)
				{
					orgId = orgIdList.substring(0, slashLocation);
					orgIdList = orgIdList.substring(slashLocation + 1);
				}
				else
					orgId = orgIdList;
				
//				if (pipeLocation > -1)
//				{
//					orgName = orgNameList.substring(1, pipeLocation);
//					orgNameList = orgNameList.substring(pipeLocation);
//				}
//				else
//					orgName = orgNameList.substring(1);
				
//				tenant = new ClientTenantInfo(orgId, orgName, null);
				if (log.isDebugEnabled())
				{
					log.debug("Current Org: " + orgId);
				}
				tenant = new ClientTenantInfo(orgId, orgId, null);
				tenants.add(tenant);
				
			}
		}
		
		return tenants;
	}

	/**
	 * Retrieves organization(s) from provided token. 
	 * Looks for value after ORG_IDENTIFIER in token.
	 * 
	 * @param token
	 * @return String The organization(s)
	 */
	private String getOrgsFromToken(String token) {
		//pull out organization(s)
		return getElementFromToken(token, ORG_IDENTIFIER);
	}

	/**
	 * Retrieves role(s) from provided token. 
	 * Looks for value after ROLE_IDENTIFIER in token.
	 * 
	 * @param token
	 * @return String The role(s)
	 */
	private String getRolesFromToken(String token) {
		//pull out role(s)
		return getElementFromToken(token, ROLE_IDENTIFIER);
	}

	/**
	 * Retrieves username from provided token. 
	 * Looks for value after USER_IDENTIFIER in token.
	 * 
	 * @param token
	 * @return String The username
	 */
	private String getUsernameFromToken(String token) {
		//pull out username
		return getElementFromToken(token, USER_IDENTIFIER);
	}

	/**
	 * Retrieves username from provided token. 
	 * Looks for value after USER_IDENTIFIER in token.
	 * 
	 * @param token
	 * @return String The username
	 */
	private String getDatetimeFromToken(String token) {
		//pull out username
		return getElementFromToken(token, DATE_IDENTIFIER);
	}

//	private String getAtrributesFromToken(String currentEncryptedToken) {
//		// TODO write this method if attributes are included in the future
//		//decrypt encrypted token
//		//pull out attributes
//		return currentEncryptedToken;
//	}

	/**
	 * Retrieves value from token based on supplied identifier
	 * ("username=", "orgId=", "role=")
	 * 
	 * @param token
	 * @param identifier
	 * @return String The value from the token
	 */
	private String getElementFromToken(String token, String identifier) {
		//pull out element(s)
		int identifierLength = identifier.length();
		String strElement = token.substring(token.indexOf(identifier) + identifierLength);
		int tokenSeperatorIndex = strElement.indexOf(TOKEN_SEPARATOR);
		if (tokenSeperatorIndex > -1)
		{
			strElement = strElement.substring(0, strElement.indexOf(TOKEN_SEPARATOR));
		}
		if (log.isDebugEnabled())
		{
			log.debug("strElement(s) provided, looking for data after " + identifier + " value is: " + strElement);
		}
		return strElement;	
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

	/**
	 * Retrieves the token from the give request object
	 * 
	 * @param req
	 * @return String The token from the request, null if not found
	 */
	private String getToken(ServletRequest req) {
		String aToken = req.getParameter(authToken);
		if (aToken != null) {
			aToken = aToken.trim();
		}
		return aToken;
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