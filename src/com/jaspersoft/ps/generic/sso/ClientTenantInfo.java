package com.jaspersoft.ps.generic.sso;

/**
 * @author aperera@jaspersoft.com, 2013
 * modified: mbielkie@tibco.com, 2015
 * modified: jhuber@tibco.com, 2015
 */
import java.io.Serializable;

import com.jaspersoft.jasperserver.multipleTenancy.MTUserDetails.TenantInfo;

public class ClientTenantInfo implements TenantInfo, Serializable {

	private static final long serialVersionUID = 4357843572490382761L;

	private String id;
	private String label;
	private String description;

	public ClientTenantInfo(String id, String label, String description) {
		this.id = id;
		this.label = label;
		this.description = description;
	}

	@Override
	public String getId() {
		return id;
	}

	@Override
	public String getLabel() {
		return label;
	}

	@Override
	public String getDescription() {
		return description;
	}
	
	public String toString() {
		return ("ID|Label|Description : " + getId() + "|" + getLabel() + "|" + getDescription() + "\n");
	}

}
