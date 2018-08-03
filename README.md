# ADFSCompatibleADUserStore
ADFS compatiable custom user Store for WSO2 Identity Server   
This is a wrapper class provides attribute compatability with ADFS
claim sets generatd by WSO2
Initially this project was simply a way to correctly encode the objectGUID
for use by Office 365 SAML or WS-Federation SSO, when the tenant was using
Microsoft directory sync technology.
It has grown to include the ability to generate most of the ADFS claim types
that WSO2 does not nativly support.

Basically, what we have several virtual properties that you can query, and when you do it triggers a suite of lookup and text replacements. 
It also solves some issues with the way WSO2 ignores AD schema in favor of LDAP schema. As we know, Microsoft does things their way, and the
WSO2 developers seem to intentionally ignore what they do in favor of what they “should do”.  In order to activate a virtual property in a 
claim, you simply treat It like an AD directory attribute in the claim definition. 
The virtual properties are :
•	fullyQualifiedDomainName: This returns the DNS domain of the domain for the user. If the user is in a sub domain, it correctly queries the configuration container and gets the registered domain name (e.g. balsamic.local).
•	netBIOSDomainName: This returns the NT4 netbios domain name. If the user is in a sub domain, it correctly queries the configuration container and gets the registered domain name (e.g. BALSAMIC)
•	tokenGroupsAsSids: This returns the users group membership, inclusive of all groups including nested ones, as SIDS (similar to the ADFS claim of the same name).
•	tokenGroupsQualifiedByDomainName: This returns the users group membership, inclusive of all groups including nested ones, as NETBIOSDOMAINNAME\SAMACCOUNTNAME (similar to the ADFS claim of the same name).
•	tokenGroupsQualifiedByLongDomainName: This returns the users group membership, inclusive of all groups including nested ones, as DNSDOMAIN.NET\ SAMACCOUNTNAME (similar to the ADFS claim of the same name).
•	tokenGroupsUnqualifiedNames This returns the users group membership, inclusive of all groups including nested ones, as their SAMACCOUNTNAME (similar to the ADFS claim of the same name).

For the above claims to work, you need to add objectSID and tokenGroups as binary attributes. You can also add tokenGroupsGlobalAndUniversal instead of tokenGroups 
and you will only get global group and universal group membership.

In addition to these properties, if you request the objectSID property, it will come back as a properly formated SID string and not as a base64 encoded string. 
So you can use that for a user claim to issue the claim for primarySid. 
