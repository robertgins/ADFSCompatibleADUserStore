/*
@author robert.ginsburg (robert.ginsburg@balsamicsolutions.com)
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

 */
package com.balsamicsolutions.wso2is;

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import javax.naming.NamingEnumeration;
import javax.naming.NamingException;

import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.naming.ldap.LdapName;

import java.util.ArrayList;

import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.naming.InvalidNameException;
import javax.naming.ldap.Rdn;

import org.wso2.carbon.CarbonConstants;
import org.wso2.carbon.user.core.ldap.ActiveDirectoryUserStoreManager;
import org.wso2.carbon.user.core.ldap.LDAPConstants;
import org.wso2.carbon.user.api.RealmConfiguration;
import org.wso2.carbon.user.core.UserCoreConstants;
import org.wso2.carbon.user.core.UserRealm;
import org.wso2.carbon.user.core.UserStoreException;
import org.wso2.carbon.user.core.claim.ClaimManager;
import org.wso2.carbon.user.core.profile.ProfileConfigurationManager;
import org.wso2.carbon.user.core.util.JNDIUtil;
import java.util.Timer;
import java.util.TimerTask;

/**
 * Instead of cloning the entire active directory implementation, we cloned only
 * the minimum elements and than updated the getUserPropertyValues to reverse
 * out the work done to represent binary entries that might be GUID's as their
 * canonical representation. This was intentionally done by WSO2 developers in
 * IDENTITY-4488 and CARBON-16026 but it breaks the default claim type of a
 * base64 encoded value expected by Office365 SAML and WSFederation integration
 * we also support several new attributes which give this store parity
 * with ADFS. Some of them are complex attribute calculations that reconcile
 * token groups instead of the more simplistic LDAP membership chasing 
 * This is because token groups are the technically correct way to represent
 * AD  group  membership for all group types. LDAP membership chasing will only get 
 * some of the users group memberships. 
 */
public class ADFSCompatibleADUserStore extends ActiveDirectoryUserStoreManager {

    private static final String MULTI_ATTRIBUTE_SEPARATOR = "MultiAttributeSeparator";

    //these are our virtual/calculated properties that we can define and
    //send as claims for a user, they can also be used to calculate the role of a user
    private static final String TOKEN_GROUPS_AS_SIDS_VIRTUAL_ATTRIBUTE_NAME = "tokenGroupsAsSids";
    private static final String TOKEN_GROUPS_QUALIFIED_BY_DOMAIN_NAME_VIRTUAL_ATTRIBUTE_NAME = "tokenGroupsQualifiedByDomainName";
    private static final String TOKEN_GROUPS_QUALIFIED_BY_LONG_DOMAIN_NAME_VIRTUAL_ATTRIBUTE_NAME = "tokenGroupsQualifiedByLongDomainName";
    private static final String TOKEN_GROUPS_UNQUALIFIED_NAME_VIRTUAL_ATTRIBUTE_NAME = "tokenGroupsUnqualifiedNames";
    private static final String SAM_ACCOUNT_NAME_QUALIFIED_BY_DOMAIN_NAME_VIRTUAL_ATTRIBUTE_NAME = "sAMAccountNameQualifiedByDomainName";
    private static final String SAM_ACCOUNT_NAME_QUALIFIED_BY_LONG_DOMAIN_NAME_VIRTUAL_ATTRIBUTE_NAME = "sAMAccountNameQualifiedByLongDomainName";

    private static final String LONG_DOMAIN_NAME_VIRTUAL_ATTRIBUTE_NAME = "fullyQualifiedDomainName";
    private static final String DOMAIN_NAME_VIRTUAL_ATTRIBUTE_NAME = "netBIOSDomainName";

    private static final String TOKEN_GROUPS = "tokenGroups";
    private static final String TOKEN_GROUPS_GLOBAL_UNIVERSAL = "tokenGroupsGlobalAndUniversal";
    private static final String SAM_ACCOUNT_NAME = "sAMAccountName";
    private static final String DISTINGUISHED_NAME = "distinguishedName";

    private String multiValueAttributeSeparator;
    private String groupSearchBasePath;
    private String groupNameAttributeName;
    private String userSearchFilter;
    private String tokenGroupAttributeName;

    private static Log sysLogger = LogFactory.getLog(ADFSCompatibleADUserStore.class);
    Map<String, Object> domainNameCache;
    SimpleExpiringCache<String, Map<String, String>> groupSidGroupNamesCache; //  minute cache for sid->group names
    SimpleExpiringCache<String, List<String>> userDistinguishedNameTokenGroupsCache; // minute cache for users token groups
    SimpleExpiringCache<String, String> userNameUserDistinguishedNameCache; // minute cache for user distinguishedName translation
    SimpleExpiringCache<String, Map<String, String>> userPropertyCache;
    private Timer cacheExpirationTimer;

    //<editor-fold defaultstate="collapsed" desc="ctor">
    /**
     * Initialize the UserStore.
     *
     */
    public ADFSCompatibleADUserStore() {

    }

    /**
     *
     * Initialize the UserStore.
     *
     * @param realmConfig
     * @param properties
     * @param claimManager
     * @param profileManager
     * @param realm
     * @param tenantId
     * @throws UserStoreException
     */
    public ADFSCompatibleADUserStore(RealmConfiguration realmConfig, Map<String, Object> properties, ClaimManager claimManager, ProfileConfigurationManager profileManager, UserRealm realm, Integer tenantId) throws UserStoreException {

        super(realmConfig, properties, claimManager, profileManager, realm, tenantId);
        checkRequiredUserStoreConfigurations();
        initializeMe();
    }

    /**
     *
     * Initialize the UserStore.
     *
     * @param realmConfig
     * @param claimManager
     * @param profileManager
     * @throws UserStoreException
     */
    public ADFSCompatibleADUserStore(RealmConfiguration realmConfig, ClaimManager claimManager, ProfileConfigurationManager profileManager) throws UserStoreException {
        super(realmConfig, claimManager, profileManager);
        checkRequiredUserStoreConfigurations();
        initializeMe();
    }

    /**
     * basic initialization of maps and caches
     */
    private void initializeMe() {

        domainNameCache = new ConcurrentHashMap<>(20);
        long commonCacheExpiration = 60 * 1000 * 30; //cache expires every 30 minutes 
        groupSidGroupNamesCache = new SimpleExpiringCache<>(commonCacheExpiration, true);               // cache for sid->group names
        userDistinguishedNameTokenGroupsCache = new SimpleExpiringCache<>(commonCacheExpiration, true); // cache for users token groups
        userNameUserDistinguishedNameCache = new SimpleExpiringCache<>(commonCacheExpiration, true);    //cache for users distinguished name
        userPropertyCache = new SimpleExpiringCache<>(commonCacheExpiration, true);                         // second user lookup cache, mostly for the dual calls from WSO2

        long timerInterval = 60 * 1000 * 5;   // process cache expiration check every 5 minutes
        cacheExpirationTimer = new Timer();
        cacheExpirationTimer.scheduleAtFixedRate(new TimerTask() {
            @Override
            public void run() {
                checkExpirations();
            }
        }, timerInterval, timerInterval);

        //only specifiy the TOKEN_GROUPS_GLOBAL_UNIVERSAL if you want to use it
        tokenGroupAttributeName = TOKEN_GROUPS;
        String binaryAttributes = realmConfig.getUserStoreProperty(LDAPConstants.LDAP_ATTRIBUTES_BINARY);
        if (null != binaryAttributes) {
            if (binaryAttributes.toUpperCase(Locale.US).contains(TOKEN_GROUPS_GLOBAL_UNIVERSAL.toUpperCase(Locale.US))) {
                tokenGroupAttributeName = TOKEN_GROUPS_GLOBAL_UNIVERSAL;
            }
        }
        multiValueAttributeSeparator = realmConfig.getUserStoreProperty(MULTI_ATTRIBUTE_SEPARATOR);
        groupSearchBasePath = realmConfig.getUserStoreProperty(LDAPConstants.GROUP_SEARCH_BASE);
        groupNameAttributeName = realmConfig.getUserStoreProperty(LDAPConstants.GROUP_NAME_ATTRIBUTE);
        userSearchFilter = realmConfig.getUserStoreProperty(LDAPConstants.USER_NAME_SEARCH_FILTER);
    }

    /**
     * in order to minimize background load, we run the timer here instead of
     * one for each expiring cache, this is called from the cacheExpirationTimer
     */
    public void checkExpirations() {
        groupSidGroupNamesCache.checkExpirations();
        userDistinguishedNameTokenGroupsCache.checkExpirations();
        userNameUserDistinguishedNameCache.checkExpirations();
        userPropertyCache.checkExpirations();
    }
    //</editor-fold>

    //<editor-fold defaultstate="collapsed" desc="finalize">
    @Override
    protected void finalize() throws Throwable {
      try{
            cacheExpirationTimer.cancel();
          }catch(Throwable t){
              throw t;
          }finally{
              super.finalize();
          }
      } 
    //</editor-fold>
  
    //<editor-fold defaultstate="collapsed" desc="wso2 entry points">
    /**
     * Implementation of getUserPropertyValues, calls our internal method
     *
     * @param userName
     * @param propertyNames
     * @param profileName
     * @return
     * @throws UserStoreException
     */
    @Override
    public Map<String, String> getUserPropertyValues(String userName, String[] propertyNames, String profileName) throws UserStoreException {
        return getUserPropertyValuesInternal(userName, propertyNames);
    }

    //</editor-fold>
    
    //<editor-fold defaultstate="collapsed" desc="getUserPropertyValuesInternal">
    /**
     * First step in handling the call from the api, we will check for our
     * virtual properties and create the dirContext
     *
     * @param userName
     * @param propertyNames
     * @return
     * @throws UserStoreException
     */
    @SuppressFBWarnings({"DM_CONVERT_CASE", "DM_DEFAULT_ENCODING"})//justification: usage is correct
    Map<String, String> getUserPropertyValuesInternal(String userName, String[] propertyNames) throws UserStoreException {
        String cacheKey = userName + String.join(multiValueAttributeSeparator, propertyNames);
        cacheKey = cacheKey.toUpperCase();
        Map<String, String> returnValue = userPropertyCache.get(cacheKey);
        if (null == returnValue) {

            List<String> propList = new ArrayList<>();
            //check for tokengroups and remove it, it will cause a deap search to fail
            //so we will get it later if we need it 
            //this is becasue we need a different search path
            boolean needSamAccountName = false;
            boolean hasSamAccountName = false;
            boolean needTokenGroups = false;
            boolean returnTokenGroupsAsSids = false;
            boolean returnTokenGroupsAsTokenGroups = false;
            boolean returnTokenGroupsQualifedWithDomainName = false;
            boolean returnTokenGroupsQualifedWithLongDomainName = false;
            boolean returnSamAccountNameQualifedWithDomainName = false;
            boolean returnSamAccountNameQualifedWithLongDomainName = false;
            boolean returnTokenGroupsAsUnqualifiedName = false;
            boolean hasDistinguishedName = false;
            boolean needDistinguishedName = false;
            boolean addFullyQualifiedDomainName = false;
            boolean addNetBIOSDomainName = false;
            //evaluate the properties and see if we have to process
            //any of the virtual ones
            for (String propertyName : propertyNames) {
                if (propertyName.equalsIgnoreCase(DISTINGUISHED_NAME)) {
                    hasDistinguishedName = true;
                }
                if (propertyName.equalsIgnoreCase(SAM_ACCOUNT_NAME)) {
                    hasSamAccountName = true;
                }
                if (propertyName.equalsIgnoreCase(tokenGroupAttributeName)) {
                    needTokenGroups = true;
                    returnTokenGroupsAsTokenGroups = true;
                } else if (propertyName.equalsIgnoreCase(TOKEN_GROUPS_AS_SIDS_VIRTUAL_ATTRIBUTE_NAME)) {
                    needTokenGroups = true;
                    returnTokenGroupsAsSids = true;
                } else if (propertyName.equalsIgnoreCase(TOKEN_GROUPS_QUALIFIED_BY_DOMAIN_NAME_VIRTUAL_ATTRIBUTE_NAME)) {
                    needTokenGroups = true;
                    returnTokenGroupsQualifedWithDomainName = true;
                } else if (propertyName.equalsIgnoreCase(TOKEN_GROUPS_QUALIFIED_BY_LONG_DOMAIN_NAME_VIRTUAL_ATTRIBUTE_NAME)) {
                    needTokenGroups = true;
                    returnTokenGroupsQualifedWithLongDomainName = true;
                } else if (propertyName.equalsIgnoreCase(TOKEN_GROUPS_UNQUALIFIED_NAME_VIRTUAL_ATTRIBUTE_NAME)) {
                    needTokenGroups = true;
                    returnTokenGroupsAsUnqualifiedName = true;
                } else if (propertyName.equalsIgnoreCase(LONG_DOMAIN_NAME_VIRTUAL_ATTRIBUTE_NAME)) {
                    needDistinguishedName = true;
                    addFullyQualifiedDomainName = true;
                } else if (propertyName.equalsIgnoreCase(DOMAIN_NAME_VIRTUAL_ATTRIBUTE_NAME)) {
                    needDistinguishedName = true;
                    addNetBIOSDomainName = true;
                } else if (propertyName.equalsIgnoreCase(SAM_ACCOUNT_NAME_QUALIFIED_BY_DOMAIN_NAME_VIRTUAL_ATTRIBUTE_NAME)) {
                    needSamAccountName = true;
                    needDistinguishedName = true;
                    returnSamAccountNameQualifedWithDomainName = true;
                } else if (propertyName.equalsIgnoreCase(SAM_ACCOUNT_NAME_QUALIFIED_BY_LONG_DOMAIN_NAME_VIRTUAL_ATTRIBUTE_NAME)) {
                    needSamAccountName = true;
                    needDistinguishedName = true;
                    returnSamAccountNameQualifedWithLongDomainName = true;
                } else {
                    propList.add(propertyName);
                }
            }

            if ((needTokenGroups || needDistinguishedName) && !hasDistinguishedName) {
                propList.add(DISTINGUISHED_NAME);
            }
            if (needSamAccountName && !hasSamAccountName) {
                propList.add(SAM_ACCOUNT_NAME);
            }
            String[] innerPropertyNames = propList.toArray(new String[propList.size()]);

            DirContext dirContext = this.connectionSource.getContext();

            try {
                //get the actual properties from AD
                returnValue = getUserPropertyValuesInternal(userName, innerPropertyNames, dirContext);
                //mark up the returned values
                if (addFullyQualifiedDomainName || addNetBIOSDomainName || returnSamAccountNameQualifedWithLongDomainName || returnSamAccountNameQualifedWithDomainName) {
                    String distinguishedName = returnValue.get(DISTINGUISHED_NAME);
                    if (addFullyQualifiedDomainName || returnSamAccountNameQualifedWithLongDomainName) {
                        String domainName = getDomainNameFromDistinguishedName(distinguishedName, true);
                        if (addFullyQualifiedDomainName) {
                            returnValue.put(LONG_DOMAIN_NAME_VIRTUAL_ATTRIBUTE_NAME, domainName);
                        }
                        if (returnSamAccountNameQualifedWithLongDomainName) {
                            String samAccountName = domainName + "\\" + returnValue.get(SAM_ACCOUNT_NAME);
                            returnValue.put(SAM_ACCOUNT_NAME_QUALIFIED_BY_LONG_DOMAIN_NAME_VIRTUAL_ATTRIBUTE_NAME, samAccountName);
                        }
                    }
                    if (addNetBIOSDomainName || returnSamAccountNameQualifedWithDomainName) {
                        String netBIOSName = getDomainNameFromDistinguishedName(distinguishedName, false);
                        if (addNetBIOSDomainName) {
                            returnValue.put(DOMAIN_NAME_VIRTUAL_ATTRIBUTE_NAME, netBIOSName);
                        }
                        if (returnSamAccountNameQualifedWithDomainName) {
                            String samAccountName = netBIOSName + "\\" + returnValue.get(SAM_ACCOUNT_NAME);
                            returnValue.put(SAM_ACCOUNT_NAME_QUALIFIED_BY_DOMAIN_NAME_VIRTUAL_ATTRIBUTE_NAME, samAccountName);
                        }
                    }
                }
                if (needTokenGroups) {
                    String userDistinguishedName = returnValue.get(DISTINGUISHED_NAME);
                    String[] userTokenGroups = getUsersTokenGroups(userDistinguishedName, dirContext);
                    Map<String, Map<String, String>> nameMap = getNamesForTokenGroups(userTokenGroups, dirContext, userDistinguishedName);

                    if (returnTokenGroupsAsSids || returnTokenGroupsAsTokenGroups) {
                        String stringifiedValue = assembleStringifiedValue(nameMap, TOKEN_GROUPS_AS_SIDS_VIRTUAL_ATTRIBUTE_NAME);
                        if (returnTokenGroupsAsSids) {
                            returnValue.put(TOKEN_GROUPS_AS_SIDS_VIRTUAL_ATTRIBUTE_NAME, stringifiedValue);
                        }
                        if (returnTokenGroupsAsTokenGroups) {
                            returnValue.put(TOKEN_GROUPS, stringifiedValue);
                        }
                    }
                    if (returnTokenGroupsAsUnqualifiedName) {
                        String stringifiedValue = assembleStringifiedValue(nameMap, TOKEN_GROUPS_UNQUALIFIED_NAME_VIRTUAL_ATTRIBUTE_NAME);
                        returnValue.put(TOKEN_GROUPS_UNQUALIFIED_NAME_VIRTUAL_ATTRIBUTE_NAME, stringifiedValue);

                    }
                    if (returnTokenGroupsQualifedWithLongDomainName) {
                        String stringifiedValue = assembleStringifiedValue(nameMap, TOKEN_GROUPS_QUALIFIED_BY_LONG_DOMAIN_NAME_VIRTUAL_ATTRIBUTE_NAME);
                        returnValue.put(TOKEN_GROUPS_QUALIFIED_BY_LONG_DOMAIN_NAME_VIRTUAL_ATTRIBUTE_NAME, stringifiedValue);

                    }
                    if (returnTokenGroupsQualifedWithDomainName) {
                        String stringifiedValue = assembleStringifiedValue(nameMap, TOKEN_GROUPS_QUALIFIED_BY_DOMAIN_NAME_VIRTUAL_ATTRIBUTE_NAME);
                        returnValue.put(TOKEN_GROUPS_QUALIFIED_BY_DOMAIN_NAME_VIRTUAL_ATTRIBUTE_NAME, stringifiedValue);
                    }

                }

            } finally {
                JNDIUtil.closeContext(dirContext);
            }
            userPropertyCache.put(cacheKey, returnValue);
        }
        return returnValue;
    }

    /**
     * This method is a variation of the ReadOnlyLDAPUserStoreManager and
     * adjusted to more accurately reflect the requirements for Microsoft Azure
     * Directories and Office 365 for Eduction implementations where the
     * ObjectGUID attribute is base64 encoded "as is" and not treated as little
     * endian We also provide support for "tokenGroups" as sid strings in the
     * same format as ADFS
     *
     * @param userName
     * @param propertyNames
     * @param dirContext
     * @return
     * @throws UserStoreException
     */
    @SuppressFBWarnings({"DM_CONVERT_CASE", "DM_DEFAULT_ENCODING"})//justification: usage is correct
    Map<String, String> getUserPropertyValuesInternal(String userName, String[] propertyNames, DirContext dirContext) throws UserStoreException {

        String userAttributeSeparator = ",";
        Map<String, String> returnValue = new HashMap<>();
        // if user name contains domain name, remove domain name
        String[] userNames = userName.split(CarbonConstants.DOMAIN_SEPARATOR);
        if (userNames.length > 1) {
            userName = userNames[1];
        }

        String searchFilter = userSearchFilter.replace("?", escapeSpecialCharactersForFilter(userName));

        NamingEnumeration<?> userAnswer = null;
        NamingEnumeration<?> attributeValues = null;
        try {

            userAnswer = this.searchForUser(searchFilter, propertyNames, dirContext);
            while (userAnswer.hasMoreElements()) {
                SearchResult userResult = (SearchResult) userAnswer.next();
                Attributes userAttributes = userResult.getAttributes();
                if (userAttributes != null) {
                    for (String propertyName : propertyNames) {
                        if (propertyName != null) {
                            Attribute userAttribute = userAttributes.get(propertyName);
                            if (userAttribute != null) {
                                StringBuilder attrBuffer = new StringBuilder();
                                for (attributeValues = userAttribute.getAll(); attributeValues.hasMore();) {
                                    Object attObject = attributeValues.next();
                                    String attributeValue = null;
                                    if (attObject instanceof String) {
                                        attributeValue = (String) attObject;
                                    } else if (attObject instanceof byte[]) {
                                        // return canonical representation of UUIDs or base64 encoded string of other binary data
                                        // except for the active Directory attribute: objectGUID, which must be base64 encoded
                                        //to be compatiable with the AzureDirectorySync default configuration
                                        final byte[] attributeBytes = (byte[]) attObject;
                                        //easier and faster to compare as upper case
                                        String normalName = propertyName.toUpperCase();
                                        if (attributeBytes.length == 16 && normalName.endsWith("UID")) {
                                            //patching CARBON-16026 by base64 encoding objectGUID
                                            //instead of treating it as little-endian and UUID printing
                                            //it, also added ignoreCase 
                                            if (normalName.equals("OBJECTGUID")) {
                                                attributeValue = new String(Base64.encodeBase64((byte[]) attObject));
                                            } else {
                                                final java.nio.ByteBuffer bb = java.nio.ByteBuffer.wrap(attributeBytes);
                                                attributeValue = new java.util.UUID(bb.getLong(), bb.getLong()).toString();
                                            }
                                        } else {
                                            //If we are asking for the SID, then convert it to the
                                            //Microsoft format of the sid string 
                                            //https://technet.microsoft.com/en-us/library/cc962011.aspx
                                            if (normalName.equals("OBJECTSID")) {
                                                attributeValue = convertSidToStr((byte[]) attObject);
                                            } else {
                                                attributeValue = new String(Base64.encodeBase64((byte[]) attObject));
                                            }
                                        }
                                    }
                                    if (attributeValue != null && attributeValue.trim().length() > 0) {
                                        if (multiValueAttributeSeparator != null && !multiValueAttributeSeparator.trim().isEmpty()) {
                                            userAttributeSeparator = multiValueAttributeSeparator;
                                        }
                                        attrBuffer.append(attributeValue).append(userAttributeSeparator);
                                    }
                                    String responseValue = attrBuffer.toString();

                                    /*
                                     * Length needs to be more than userAttributeSeparator.length() for a valid
                                     * attribute, since we
                                     * attach userAttributeSeparator
                                     */
                                    if (responseValue.trim().length() > userAttributeSeparator.length()) {
                                        responseValue = responseValue.substring(0, responseValue.length() - userAttributeSeparator.length());
                                        returnValue.put(propertyName, responseValue);
                                    }

                                }
                            }
                        }
                    }
                }
            }

        } catch (NamingException e) {
            String errorMessage = "Error occurred while getting user property values for user : " + userName;
            if (sysLogger.isDebugEnabled()) {
                sysLogger.debug(errorMessage, e);
            }
            throw new UserStoreException(errorMessage, e);
        } finally {
            // close the naming enumeration and free up resources
            JNDIUtil.closeNamingEnumeration(attributeValues);
            JNDIUtil.closeNamingEnumeration(userAnswer);

        }
        return returnValue;
    }
    //</editor-fold>

    //<editor-fold defaultstate="collapsed" desc="token group queries">
    /**
     * gets token groups for a user as an array of SID strings
     *
     * @param userDistinguishedName
     * @param dirContext
     * @return
     */
    private String[] getUsersTokenGroups(String userDistinguishedName, DirContext dirContext) {

        boolean addToCache = false;
        List<String> returnValue = userDistinguishedNameTokenGroupsCache.get(userDistinguishedName);
        if (returnValue == null) {
            addToCache = true;
            returnValue = new ArrayList<>();
        }
        String userReturnedAtts[] = {tokenGroupAttributeName};
        try {

            Attributes userAttributes = dirContext.getAttributes(userDistinguishedName, userReturnedAtts);
            //TODO: check to see if this namingenumeration needs to be closed or if enumerator does it
            for (NamingEnumeration attributeEnum = userAttributes.getAll(); attributeEnum.hasMore();) {
                Attribute sidAttribute = (Attribute) attributeEnum.next();
                for (NamingEnumeration e = sidAttribute.getAll(); e.hasMore();) {
                    byte[] sidBytes = (byte[]) e.next();
                    String sidString = convertSidToStr(sidBytes);
                    returnValue.add(sidString);
                }
            }
            if (addToCache) {
                userDistinguishedNameTokenGroupsCache.put(userDistinguishedName, returnValue);
            }
        } catch (NamingException attributeError) {
            String errorMessage = "Problem getting tokenGroups by distinguished name: " + attributeError;
            if (sysLogger.isDebugEnabled()) {
                sysLogger.debug(errorMessage, attributeError);
            }
        }
        return returnValue.toArray(new String[returnValue.size()]);
    }

    /**
     * Looks up tokengroups (sid strings) and gets all name variations for them
     * the cache is checked first for values and then the AD lookup routine is
     * called
     *
     * @param tokenGroups
     * @param dirContext
     * @param userDistinguishedName
     * @return
     */
    private Map<String, Map<String, String>> getNamesForTokenGroups(String[] tokenGroups, DirContext dirContext, String userDistinguishedName) {
        Map<String, Map<String, String>> returnValue = new HashMap<>();
        List<String> uncachedNames = new ArrayList<>();
        //first try the cache
        for (String groupSid : tokenGroups) {
            Map<String, String> groupNames = groupSidGroupNamesCache.get(groupSid);
            if (groupNames == null) {
                uncachedNames.add(groupSid);
            } else {
                returnValue.put(groupSid, groupNames);
            }
        }
        //now lookup all the uncached items
        while (uncachedNames.size() > 0) {
            //technically the limit to the size of the query we send to AD is 10MEG, however
            //I have seen this randomly not work correctly in remote LDAP (over the internet)
            //Likely it is something to do with slower connectivity. Regardless, we batch this
            //up into smaller queries of 50 SID's at a time to avoid any issues with filter
            //string length
            List<String> nameBatch = new ArrayList<>();
            while (nameBatch.size() < 50 && uncachedNames.size() > 0) {
                nameBatch.add(uncachedNames.remove(0));
            }
            Map<String, Map<String, String>> nameMap = lookupNamesForTokenGroups(nameBatch.toArray(new String[nameBatch.size()]), dirContext, userDistinguishedName);
            for (Map.Entry<String, Map<String, String>> entry : nameMap.entrySet()) {
                String groupSid = entry.getKey();
                Map<String, String> groupNames = entry.getValue();
                groupSidGroupNamesCache.put(groupSid, groupNames);
                returnValue.put(groupSid, groupNames);
            }
        }
        return returnValue;
    }

    /**
     * Looks up tokengroups (sid strings) and gets all name variations for them
     * from AD
     *
     * @param tokenGroups
     * @param dirContext
     * @param userDistinguishedName
     * @return
     */
    private Map<String, Map<String, String>> lookupNamesForTokenGroups(String[] tokenGroups, DirContext dirContext, String userDistinguishedName) {
        Map<String, Map<String, String>> returnValue = new HashMap<>();
        if (tokenGroups.length > 0) {
            //first build the search filter
            StringBuilder groupsSearchFilter = new StringBuilder();
            groupsSearchFilter.append("(|");
            for (String groupSid : tokenGroups) {
                groupsSearchFilter.append("(objectSid=");
                groupsSearchFilter.append(groupSid);
                groupsSearchFilter.append(")");
            }
            groupsSearchFilter.append(")");
            String netBIOSName = getDomainNameFromDistinguishedName(userDistinguishedName, false);
            String domainName = getDomainNameFromDistinguishedName(userDistinguishedName, true);
            returnValue = lookupGroupNamesForSearchFilter(groupsSearchFilter.toString(), dirContext, netBIOSName, domainName);
        }
        return returnValue;
    }

    /**
     * Looks up group in AD information based on a search filter
     *
     * @param groupsSearchFilter
     * @param dirContext
     * @param netBIOSName
     * @param domainName
     * @return
     */
    private Map<String, Map<String, String>> lookupGroupNamesForSearchFilter(String groupsSearchFilter, DirContext dirContext, String netBIOSName, String domainName) {
        Map<String, Map<String, String>> returnValue = new HashMap<>();
        SearchControls groupsSearchCtls = new SearchControls();
        groupsSearchCtls.setSearchScope(SearchControls.SUBTREE_SCOPE);
        String[] groupsReturnedAtts = new String[]{groupNameAttributeName, "objectSid"};
        if (!groupNameAttributeName.equalsIgnoreCase(SAM_ACCOUNT_NAME)) {
            groupsReturnedAtts = new String[]{groupNameAttributeName, "objectSid", SAM_ACCOUNT_NAME};
        }
        groupsSearchCtls.setReturningAttributes(groupsReturnedAtts);
        NamingEnumeration groupsAnswer = null;

        try {
            groupsAnswer = dirContext.search(groupSearchBasePath, groupsSearchFilter, groupsSearchCtls);
            while (groupsAnswer.hasMoreElements()) {
                SearchResult groupResult = (SearchResult) groupsAnswer.next();
                Attributes groupAttributes = groupResult.getAttributes();
                //now do all the work to parse the group into the names we need
                if (groupAttributes != null) {
                    //add all of the possible name variations
                    String samAccountName = (String) groupAttributes.get(SAM_ACCOUNT_NAME).get();
                    byte[] sidBytes = (byte[]) groupAttributes.get("objectSid").get();
                    String groupSid = convertSidToStr(sidBytes);
                    Map<String, String> groupNames = new HashMap<>();
                    groupNames.put(TOKEN_GROUPS_AS_SIDS_VIRTUAL_ATTRIBUTE_NAME, groupSid);
                    String groupName = (String) groupAttributes.get(groupNameAttributeName).get();
                    //special case where tokenGroups is MemberOf attribute in QL
                    groupNames.put(TOKEN_GROUPS, groupName);
                    groupNames.put(groupNameAttributeName, groupName);
                    String longName = domainName + "\\" + samAccountName;
                    String nt4Name = netBIOSName + "\\" + samAccountName;
                    groupNames.put(TOKEN_GROUPS_AS_SIDS_VIRTUAL_ATTRIBUTE_NAME, groupSid);
                    groupNames.put(TOKEN_GROUPS_QUALIFIED_BY_DOMAIN_NAME_VIRTUAL_ATTRIBUTE_NAME, nt4Name);
                    groupNames.put(TOKEN_GROUPS_QUALIFIED_BY_LONG_DOMAIN_NAME_VIRTUAL_ATTRIBUTE_NAME, longName);
                    groupNames.put(TOKEN_GROUPS_UNQUALIFIED_NAME_VIRTUAL_ATTRIBUTE_NAME, samAccountName);

                    returnValue.put(groupSid, groupNames);
                }
            }
        } catch (NamingException searchError) {
            String errorMessage = "Problem finding groups by SID: " + searchError;
            if (sysLogger.isDebugEnabled()) {
                sysLogger.debug(errorMessage, searchError);
            }
        } finally {
            JNDIUtil.closeNamingEnumeration(groupsAnswer);
        }

        return returnValue;
    }

    //</editor-fold>
    
    //<editor-fold defaultstate="collapsed" desc="naming context and netbios names and ldap lookups">
    /**
     * Lookup user distinguishedName in cache or AD
     *
     * @param userName
     * @param dirContext
     * @return
     * @throws UserStoreException
     */
    String getUserDistinguishedName(String userName, DirContext dirContext) throws UserStoreException {
        String returnValue = userNameUserDistinguishedNameCache.get(userName);
        if (returnValue == null) {
            String[] propertyNames = new String[]{DISTINGUISHED_NAME};
            Map<String, String> userProps = getUserPropertyValuesInternal(userName, propertyNames, dirContext);
            returnValue = userProps.get(DISTINGUISHED_NAME);
            userNameUserDistinguishedNameCache.put(userName, returnValue);
        }
        return returnValue;
    }

    /**
     * Gets the domain naming context so we can find configuration entries
     *
     * @param dirContext
     * @return
     */
    String getConfigurationNamingContext(DirContext dirContext) {
        String returnValue = "";
        try {
            Attributes rootAttributes = dirContext.getAttributes("", new String[]{"configurationNamingContext",});
            returnValue = (String) rootAttributes.get("configurationNamingContext").get();
        } catch (NamingException attributeError) {
            if (sysLogger.isDebugEnabled()) {
                String errorMessage = "Error occurred in getNamingContext " + attributeError;
                sysLogger.debug(errorMessage, attributeError);
            }
        }
        return returnValue;
    }

    /**
     * Returns the netbios and fully qualified name from cache or AD element 0
     * is the netbios name, element 1 is the FQDN
     *
     * @param domainPath
     * @return
     */
    @SuppressFBWarnings({"DM_CONVERT_CASE", "DM_DEFAULT_ENCODING"})//justification: usage is correct
    String[] getDomainNamesFromLDAP(String domainPath) {
        DirContext dirContext = null;

        String[] returnValue = new String[]{"UNKNOWN", "UNKNOWN.UNKNOWN"};
        NamingEnumeration configAnswer = null;

        try {
            dirContext = this.connectionSource.getContext();
            String namingContext = getConfigurationNamingContext(dirContext);
            if (namingContext != null && namingContext.length() > 0) {
                String configPath = "CN=Partitions," + namingContext;
                String searchFilter = "(&(objectClass=crossRef)(nCName=" + domainPath + "))";
                String returnedAtts[] = {"dnsRoot", "nETBIOSName", "nCName"};
                SearchControls searchCtls = new SearchControls();
                searchCtls.setSearchScope(SearchControls.SUBTREE_SCOPE);
                searchCtls.setReturningAttributes(returnedAtts);
                try {
                    configAnswer = dirContext.search(configPath, searchFilter, searchCtls);
                    //we should only get one, unless replication has one staged
                    while (configAnswer.hasMoreElements()) {
                        SearchResult configResult = (SearchResult) configAnswer.next();
                        Attributes configAttributes = configResult.getAttributes();
                        String nCName = (String) configAttributes.get("nCName").get();
                        if (nCName.equalsIgnoreCase(domainPath)) {
                            String dnsRoot = (String) configAttributes.get("dnsRoot").get();
                            String nETBIOSName = (String) configAttributes.get("nETBIOSName").get();
                            if (dnsRoot != null && nETBIOSName != null) {
                                returnValue[0] = nETBIOSName.toUpperCase();
                                returnValue[1] = dnsRoot.toUpperCase();
                            }
                        }
                    }
                } catch (NamingException searchError) {
                    String errorMessage = "Problem finding configuration by path " + domainPath;
                    if (sysLogger.isDebugEnabled()) {
                        sysLogger.debug(errorMessage, searchError);
                    }
                }
            }
        } catch (UserStoreException e) {
            if (sysLogger.isDebugEnabled()) {
                String errorMessage = "Error occurred in getDomainNamesFromLDAP : " + domainPath;
                sysLogger.debug(errorMessage, e);
            }
        } finally {
            try {
                JNDIUtil.closeNamingEnumeration(configAnswer);
                JNDIUtil.closeContext(dirContext);
            } catch (UserStoreException e) {

                if (sysLogger.isDebugEnabled()) {
                    String errorMessage = "Error cleaning up from getDomainNamesFromLDAP : " + domainPath;
                    sysLogger.debug(errorMessage, e);
                }
            }

        }
        return returnValue;
    }

    /**
     * Returns the netbios or fully qualified name from cache or LDAP, these
     * cannot be change in an AD forest, so we can cache them forever in a
     * single domain, we will only have two entries, in a forest we will have
     * one for each domain
     *
     * @param distinguishedName
     * @param returnFQDN
     * @return
     */
    String getDomainNameFromDistinguishedName(String distinguishedName, boolean returnFQDN) {
        String returnValue = "UNKNOWN";
        String domainPath = domainPathFromDistinguishedName(distinguishedName);
        String cacheKey = domainPath;
        if (domainPath.length() > 0) {
            if (returnFQDN) {
                cacheKey += "FQDN";
            } else {
                cacheKey += "NETBIOS";
            }
            returnValue = (String) domainNameCache.get(cacheKey);
        }
        if (returnValue == null || returnValue.length() == 0) {
            //not found in cache so get them and cache them , they dont change
            //so we dont need to put them in an expiring cache
            String[] domainNames = getDomainNamesFromLDAP(domainPath);
            if (domainNames.length == 2) {
                //only cache if wer are valid
                if (domainNames[0] != null && domainNames[1] != null
                        && !domainNames[0].equals("UNKNOWN")
                        && !domainNames[1].equals("UNKNOWN.UNKNOWN")) {
                    String cacheKeyNetBios = domainPath + "NETBIOS";
                    String cacheKeyFQDN = domainPath + "FQDN";

                    domainNameCache.put(cacheKeyNetBios, domainNames[0]);
                    domainNameCache.put(cacheKeyFQDN, domainNames[1]);
                    if (returnFQDN) {
                        returnValue = domainNames[1];
                    } else {
                        returnValue = domainNames[0];
                    }
                }
            }
        }
        return returnValue;
    }
    //</editor-fold>

    //<editor-fold defaultstate="collapsed" desc="escaping and stringifying utilities">
    /**
     * returns the segment of the domain path that starts at DC=
     *
     * @param distinguishedName
     * @return
     */
    static String domainPathFromDistinguishedName(String distinguishedName) {
        String returnValue = "";
        String rdnSeperator = "";
        try {
            LdapName ldapDN = new LdapName(distinguishedName);
            List<Rdn> ldapRDNs = ldapDN.getRdns();
            for (int rdnIdx = 0; rdnIdx < ldapRDNs.size(); rdnIdx++) {
                String oneRdn = ldapRDNs.get(rdnIdx).toString();
                if (oneRdn.startsWith("DC=") || oneRdn.startsWith("dc=")) {
                    returnValue = oneRdn + rdnSeperator + returnValue;
                    rdnSeperator = ",";
                } else {
                    //once we are past the DC= we dont need to evaluate any more
                    break;
                }
            }
        } catch (InvalidNameException ex) {
            Logger.getLogger(ADFSCompatibleADUserStore.class.getName()).log(Level.SEVERE, null, ex);
        }

        return returnValue;
    }

    /**
     * creates single delimited string from an array of values in all of the
     * mapped collections
     *
     * @param nameMap
     * @param keyName
     * @return
     */
    String assembleStringifiedValue(Map<String, Map<String, String>> nameMap, String keyName) {

        List<String> itemValues = new ArrayList<>();
        for (Map.Entry<String, Map<String, String>> entry : nameMap.entrySet()) {
            Map<String, String> groupNames = entry.getValue();
            String itemValue = groupNames.get(keyName);
            if (itemValue != null && itemValue.length() > 0) {
                itemValues.add(itemValue);
            }
        }
        return String.join(multiValueAttributeSeparator, itemValues);
    }

    /**
     * Converts Windows SID to a String. NULL input returns NULL. Invalid byte
     *
     * @param sid
     * @return
     */
    static String convertSidToStr(byte[] sid) {
        if (sid == null) {
            return "NULL SID";
        }
        if (sid.length < 8 || sid.length % 4 != 0) {
            return "INVALID SID";
        }
        StringBuilder returnValue = new StringBuilder();
        returnValue.append("S-").append(sid[0]);
        int subAuthCount = sid[1]; // Init with Subauthority Count.
        ByteBuffer sidBytes = ByteBuffer.wrap(sid); // default big endian.
        returnValue.append("-").append((long) sidBytes.getLong() & 0XFFFFFFFFFFFFL);
        sidBytes.order(ByteOrder.LITTLE_ENDIAN); // Now switch.
        for (int i = 0; i < subAuthCount; i++) { // Create Subauthorities.
            returnValue.append("-").append((long) sidBytes.getInt() & 0xFFFFFFFFL);
        }
        return returnValue.toString();
    }

    /**
     * This method copied from ActiveDirectoryUserStoreManager because it was
     * private and reflection is slow
     *
     * @param dnPartial
     * @return
     */
    private String escapeSpecialCharactersForFilter(String dnPartial) {
        boolean replaceEscapeCharacters = true;

        String replaceEscapeCharactersAtUserLoginString = realmConfig
                .getUserStoreProperty(UserCoreConstants.RealmConfig.PROPERTY_REPLACE_ESCAPE_CHARACTERS_AT_USER_LOGIN);

        if (replaceEscapeCharactersAtUserLoginString != null) {
            replaceEscapeCharacters = Boolean
                    .parseBoolean(replaceEscapeCharactersAtUserLoginString);
            if (sysLogger.isDebugEnabled()) {
                sysLogger.debug("Replace escape characters configured to: "
                        + replaceEscapeCharactersAtUserLoginString);
            }
        }
        //TODO: implement character escaping for *

        if (replaceEscapeCharacters) {
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < dnPartial.length(); i++) {
                char currentChar = dnPartial.charAt(i);
                switch (currentChar) {
                    case '\\':
                        sb.append("\\5c");
                        break;
//                case '*':
//                    sb.append("\\2a");
//                    break;
                    case '(':
                        sb.append("\\28");
                        break;
                    case ')':
                        sb.append("\\29");
                        break;
                    case '\u0000':
                        sb.append("\\00");
                        break;
                    default:
                        sb.append(currentChar);
                }
            }
            return sb.toString();
        } else {
            return dnPartial;
        }
    }

    //</editor-fold>
}
