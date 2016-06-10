package com.jaspersoft.ps.generic.sso;

import java.io.IOException;
import java.io.InputStream;
import java.io.StringWriter;
import java.net.HttpURLConnection;
import java.net.URL;

import org.apache.commons.io.IOUtils;
import org.json.JSONObject;

public class util {

	public static JSONObject GetJSONfromURL(String bearer, String validTokenEndpoint)
	{
		
		//get user info for the user, including roles and attributes (this is using POST)
		String userInfoStr = null;
		
		/*
		 * for debugging and testing.
		 * 
		 * 
		 
		 HttpURLConnection conn = null;

		try {
			String urlStr = validTokenEndpoint;
			
			URL url = new URL(urlStr);

			conn = (HttpURLConnection) url.openConnection();
			conn.setRequestMethod("GET");
			conn.setDoOutput(true); //this is for POST and PUT
			conn.setDoInput(true); //this is for GET
			conn.setUseCaches(false);
			conn.setAllowUserInteraction(false);
			conn.setRequestProperty("Authorization", "Bearer " + bearer);
			if (conn.getResponseCode() != 200)
				return null;


			//Get Response
			InputStream is = conn.getInputStream();
			userInfoStr = convertInputStream2String(is);

		} catch (Exception e) {
		} finally {
			if(conn != null) {
				conn.disconnect();
			}
		}
	*/
		JSONObject json = null;
		
		//for debugging:
		userInfoStr = "{\"CurrentOperationId\": 123,\"CurrentOperationName\": \"Jason 123\",\"Username\": \"Jason Huber\",\"FullName\": \"Jasper Reporting\",\"Roles\": [\"ROLE_BOOKKEEPER\", \"ROLE_FRONTDESK\"],\"Attributes\": {\"OperationIds\": \"123\",\"OperationNumbers\": \"123123123\"}}";
		
		try
		{
			json = new JSONObject(userInfoStr);
		}
		catch(Exception e) {
		}
		return json;
		
	}
	
	protected static String convertInputStream2String(InputStream is) throws IOException
	{
		StringWriter writer = new StringWriter();
		IOUtils.copy(is, writer, "UTF-8");
		return writer.toString().trim();
	}
	
	
}
