package com.balsamicsolutions.wso2is.internal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.osgi.service.component.ComponentContext;

import org.wso2.carbon.user.api.UserStoreManager;
import org.wso2.carbon.user.core.service.RealmService;

import com.balsamicsolutions.wso2is.ADFSCompatibleADUserStore;
import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;

/**
 * @scr.component name="com.balsamicsolutions.wso2is.component" immediate=true
 * @scr.reference name="user.realmservice.default"
 * interface="org.wso2.carbon.user.core.service.RealmService" cardinality="1..1"
 * policy="dynamic" bind="setRealmService" unbind="unsetRealmService"
 */
public class ADFSCompatibleADUserStoreMgtDSComponent {

    @SuppressWarnings("FieldMayBeFinal")//justification: wso2 provided example as best practice
    private static Log sysLogger = LogFactory.getLog(ADFSCompatibleADUserStoreMgtDSComponent.class);
    private static RealmService realmService;
    private static final String QL_VER="2.0";
    
    /**
     *
     * @param ctxt
     */
    protected void activate(ComponentContext ctxt) {

        ADFSCompatibleADUserStore ADFSCompatibleADUserStore = new ADFSCompatibleADUserStore();
        ctxt.getBundleContext().registerService(UserStoreManager.class.getName(), ADFSCompatibleADUserStore, null);
        sysLogger.info("ADFSCompatibleADUserStore bundle " + QL_VER +" activated successfully..");
    }

    /**
     *
     * @param ctxt
     */
    protected void deactivate(ComponentContext ctxt) {
        if (sysLogger.isDebugEnabled()) {
            sysLogger.debug("ADFSCompatibleADUserStore bundle " + QL_VER +" has deactivated ");
        }
    }

    /**
     *
     * @param rlmService
     */
    @SuppressFBWarnings("ST_WRITE_TO_STATIC_FROM_INSTANCE_METHOD")//justification: wso2  provided example as best practice
    protected void setRealmService(RealmService rlmService) {
       
        realmService = rlmService;
    }

    /**
     *
     * @param rlmService
     */
    @SuppressFBWarnings("ST_WRITE_TO_STATIC_FROM_INSTANCE_METHOD") //justification: wso2  provided example as best practice
    protected void unsetRealmService(RealmService rlmService) {

        //****ignore the findBugs warning for "write to static field"****
        realmService = null;
    }

    /**
     *
     * @return
     */
    public static RealmService getRealmService() {
        return realmService;
    }
}
