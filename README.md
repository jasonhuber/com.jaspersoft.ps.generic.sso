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

## this branch includes both the cipher (new) and token-base (old) code...
You do not need to do both.

For the Cipher (new) you would use the file applicationContext-externalAuth-preAuth-mt.xml

for the old you would use (change the existing in most cases) applicationContext-security-web.xml

##Why choose one over the other?

The New method is easier and somewhat more future compatible/supported.
The old way gives you a little more control since the new way relies on a formatted string.

That formatted string can be limiting due to what is included and the size of the string itself.

Both can do anything inside the decrypt or dofilter method, but the new way sends backa string and the old way actually creates a user object that you then need a post-processor to fill in the attributes...


