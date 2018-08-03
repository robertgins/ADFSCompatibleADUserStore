     Custom User Store for WSO2 Identity Server 

==========================================================
======================

this is a wrapper class that fixes the issue where the built-in WSO2
 ActiveDirectorUserStoreManager does not base64 encode ObjectGUID from Active
 Directory. Since the default Active Directory synchrhoization technology uses 
 a base64 encoded objectGUID attribute as its syncrhonization pin (a.k.a ImmutableID)
 we need to support that format if we have to support Azure. This is intended 
 as a stop gap for WSO2 IS 5.2 and WSO2 IS 5.3, until such  time as an Azure 
 compatiable provider with an engineed property syntax may or may not become available.
 
 Instead of cloning the entire active directory implementation, we cloned only
 the minimum elements and than updated the getUserPropertyValues to reverse out the
 work done to represent binary entries that might be GUID's as their canonical
 representation. This was intentionally done by WSO2 developers in
 IDENTITY-4488 and CARBON-16026 but it breaks the default claim type of a
 base64 encoded value expected by Office365 SAML and WSFederation integration

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


