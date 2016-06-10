package com.jaspersoft.ps.generic.sso;

import java.util.Iterator;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import com.jaspersoft.jasperserver.api.common.crypto.CipherI;

public class cipher implements CipherI
{
	private String validTokenEndpoint = "";

	@Override
	public String encrypt(String plainText) {
		return plainText;
	}
	@SuppressWarnings("unchecked")
	@Override
	public String decrypt(String cipherText) {
	
		
		JSONObject json = util.GetJSONfromURL(cipherText, validTokenEndpoint);
		
		//u=obama|r=PRESIDENT,HUSBAND|o=WhiteHouse|pa1=USA,Kenya|pa2=Washington -->

		String ppToken = "u=~username~|r=~roles~|o=~organization~|";

		try {
			ppToken = ppToken.replace("~username~", json.getString("Username"));
		

		//roles
		JSONArray roles = json.getJSONArray("Roles"); 
		//authorities.add(new SimpleGrantedAuthority("ROLE_USER"));
		String sroles = "";
		for (int i = 0; i < roles.length(); i++) {
			sroles += roles.getString(i) + ",";
		}
		sroles = sroles.substring(0, sroles.length()-1);
		ppToken = ppToken.replace("~roles~", sroles);
	
		//organization
		ppToken = ppToken.replace("~organization~", json.getString("CurrentOperationId"));
		
		//profile attributes
		Iterator<String> iter = json.getJSONObject("Attributes").keys();
	
		while(iter.hasNext())
		{
			String key = iter.next();
			String value = json.getJSONObject("Attributes").getString(key);
			ppToken += key + "=" +value + "|";
		}
		} catch (JSONException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	
		return ppToken;
	
	}
	

	public String getvalidTokenEndpoint() {
		return validTokenEndpoint;
	}

	public void setvalidTokenEndpoint(String validTokenEndpoint) {
		this.validTokenEndpoint = validTokenEndpoint;
	}
}