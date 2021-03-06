package com.jaspersoft.ps.generic.sso;

import java.io.Serializable;

import java.util.List;

import org.springframework.security.core.GrantedAuthority;

import com.jaspersoft.jasperserver.multipleTenancy.MTUserDetails;

/**
 * @author aperera@jaspersoft.com, 2013
 * modified: mbielkie@tibco.com, 2015
 * modified: jhuber@tibco.com, 2015
 */
public class ClientUserDetails implements MTUserDetails, Serializable {

	// private static Log log = LogFactory.getLog(ClientUserDetails.class);

	private final String username;
	private final String[][] profileAttributes;
	private final List<TenantInfo> tenants;
	private final List<GrantedAuthority> authorities;

	private final boolean enabled = true;
	private final boolean externallyDefined = true;

	private static final long serialVersionUID = 4287079258663733766L;

	public ClientUserDetails(String username, List<TenantInfo> tenants,
			List<GrantedAuthority> authorities, String[][] profileAttributes) {
		this.username = username;
		this.profileAttributes = profileAttributes;
		this.tenants = tenants;
		this.authorities = authorities;
	}

	@Override
	public String getUsername() {
		return username;
	}

	@Override
	public String getPassword() {
		return null;
	}

	public String[][] getProfileAttributes() {
		return profileAttributes;
	}

	@Override
	public boolean isEnabled() {
		return enabled;
	}

	public boolean isExternallyDefined() {
		return externallyDefined;
	}

	@Override
	public boolean isAccountNonExpired() {
		return true;
	}

	@Override
	public boolean isAccountNonLocked() {
		return true;
	}

	@Override
	public boolean isCredentialsNonExpired() {
		return true;
	}

	@Override
	public List<GrantedAuthority> getAuthorities() {
		return authorities;
	}

	@Override
	public List<TenantInfo> getTenantPath() {
		return tenants;
	}
}
