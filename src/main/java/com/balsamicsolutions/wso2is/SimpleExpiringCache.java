/*
 * @author robert.ginsburg (robert.ginsburg@balsamicsolutions.com)
 *  this is a very simple implementation of a concurrent hash that also
 *  includes an expiration processor,  
 */
package com.balsamicsolutions.wso2is;

import java.util.ArrayList;
import java.util.Date;
import java.util.Map;
import java.util.Timer;
import java.util.TimerTask;
import java.util.concurrent.ConcurrentHashMap;

/**
 * simple cache, expires on a timer interval
 *
 * @author robert.ginsburg
 * @param <K>
 * @param <V>
 */
public class SimpleExpiringCache<K, V>  {

    private static final long TEN_SECONDS = 10000;
    private Map<K, Long> expirationMap;
    private long expirationTimeInMilliseconds = TEN_SECONDS; //10 seconds is default cache
    private Timer expirationTimer;
    private final boolean internalTimer;
    private Map<K,V> valueMap;
  
    
    /**
     * CTOR
     *
     */
    public SimpleExpiringCache() {
        internalTimer = true;
        initializeMe();
    }

    /**
     * CTOR
     *
     * @param expiryInMillis
     */
    public SimpleExpiringCache(long expiryInMillis) {
        internalTimer = true;
        this.expirationTimeInMilliseconds = expiryInMillis;
        initializeMe();
    }

    /**
     * CTOR
     *
     * @param expiryInMillis
     * @param externalThread
     */
    public SimpleExpiringCache(long expiryInMillis, boolean externalThread) {
        internalTimer = !externalThread;
        this.expirationTimeInMilliseconds = expiryInMillis;
        initializeMe();
    }
    /**
     * CTOR
     *
     * @param expiryInMillis
     * @param externalThread
     */
    public SimpleExpiringCache( boolean externalThread) {
        internalTimer = !externalThread;
        initializeMe();
    }
    
     @Override
    protected void finalize() throws Throwable {
      try{
             if(internalTimer){
                expirationTimer.cancel();
             }
               
          }catch(Throwable t){
              throw t;
          }finally{
              super.finalize();
          }
      } 
    
    /**
     * Initialization
     */
    private void initializeMe() {
        expirationMap = new ConcurrentHashMap<>();
        valueMap = new ConcurrentHashMap<>();
        if (expirationTimeInMilliseconds <= 0) {
            expirationTimeInMilliseconds = TEN_SECONDS;
        }
        long timerInterval = expirationTimeInMilliseconds / 2;
        if (timerInterval < TEN_SECONDS) {
            timerInterval = TEN_SECONDS;
        }
        if (internalTimer) {
            expirationTimer = new Timer();
            expirationTimer.scheduleAtFixedRate(new TimerTask() {
                @Override
                public void run() {
                    checkExpirations();
                }
            }, timerInterval, timerInterval);
        }
    }

    /**
     * add a value , setting expiration
     *
     * @param key
     * @param value
     * @return
     */
    public V put(K key, V value) {
        long expirationTime = new Date().getTime() + expirationTimeInMilliseconds;
        expirationMap.put(key, expirationTime);
        V returnVal = valueMap.put(key, value);
        return returnVal;
    }

    /**
     * get a value, if its not expired
     *
     * @param key
     * @return
     */
    public V get(K key) {

        //we need to make sure the requested item is not expired
        long currentTime = new Date().getTime();
        if (expirationMap.containsKey(key)) {
            long expirationTime = expirationMap.get(key);
            if (currentTime > (expirationTime)) {
                //we dont delete here, the timer will eventually clean 
                //it up, but for now we return a null
                return null;
            } else {
                return valueMap.get(key);
            }
        } else {
            return null;
        }

    }

    /**
     * check all expirations
     */
    public void checkExpirations() {
        long currentTime = new Date().getTime();
        //We do the delete in two steps because the enumerator
        //can change when we delete, and we dont want to miss
        ArrayList<K> expiredEntries = new ArrayList<>();
        for (K key : expirationMap.keySet()) {
            if (currentTime > (expirationMap.get(key))) {
                expiredEntries.add(key);
            }
        }
        //ok now we have them, so remove them
        for(K deleteMe:expiredEntries){
            expirationMap.remove(deleteMe);
            valueMap.remove(deleteMe);
        }
    }
}
