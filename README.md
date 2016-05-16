# com.jaspersoft.ps.generic.sso

## Not really a JSON branch at all

This branch creates a user and sets it up manually.
it is good for 6.2.1 IF you change the referenced xml file...



### this change is necessary in 6.1.X and up to get attributes to sync...
I only had to remove the line:

&lt;security:protect
method="com.jaspersoft.jasperserver.api.metadata.user.service.ProfileAttributeService.putProfileAttribute"
access="ROLE_ADMINISTRATOR, ACL_ATTRIBUTE_USER_ADMIN"/&gt;

in applicationContext-security.xml

The ApplicationContext.xml I was able to leave alone.
