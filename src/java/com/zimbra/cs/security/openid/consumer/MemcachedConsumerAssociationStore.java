/*
 * ***** BEGIN LICENSE BLOCK *****
 * Zimbra Collaboration Suite Server
 * Copyright (C) 2011, 2013, 2014 Zimbra, Inc.
 * 
 * This program is free software: you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free Software Foundation,
 * version 2 of the License.
 * 
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 * You should have received a copy of the GNU General Public License along with this program.
 * If not, see <http://www.gnu.org/licenses/>.
 * ***** END LICENSE BLOCK *****
 */
package com.zimbra.cs.security.openid.consumer;

import com.zimbra.common.util.Log;
import com.zimbra.common.util.ZimbraLog;
import com.zimbra.common.util.memcached.ZimbraMemcachedClient;
import com.zimbra.cs.memcached.MemcachedConnector;
import org.openid4java.association.Association;
import org.openid4java.consumer.ConsumerAssociationStore;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/**
 */
public class MemcachedConsumerAssociationStore implements ConsumerAssociationStore {

    private static final String KEY_PREFIX = "zmOpenidConsumerAssoc:";
    private static Log logger = ZimbraLog.extensions;
    private static final boolean debug = logger.isDebugEnabled();

    private static ZimbraMemcachedClient memcachedClient = MemcachedConnector.getClient();

    @Override
    public synchronized void save(String opUrl, Association association) {
        @SuppressWarnings("unchecked")
        Map<String, Association> handleMap = (Map<String, Association>) memcachedClient.get(getKey(opUrl));

        if (handleMap == null)
            handleMap = new HashMap<String, Association>();
        else
            removeExpired(handleMap);

        String handle = association.getHandle();
        if (debug)
            logger.debug("Adding association: " + handle + " with OP: " + opUrl);
        handleMap.put(association.getHandle(), association);
        memcachedClient.put(getKey(opUrl), handleMap, true);
    }

    @Override
    public synchronized Association load(String opUrl, String handle) {
        @SuppressWarnings("unchecked")
        Map<String, Association> handleMap = (Map<String, Association>) memcachedClient.get(getKey(opUrl));

        if (handleMap != null) {
            removeExpired(handleMap);
            return handleMap.get(handle);
        }
        return null;
    }

    @Override
    public synchronized Association load(String opUrl) {
        @SuppressWarnings("unchecked")
        Map<String, Association> handleMap = (Map<String, Association>) memcachedClient.get(getKey(opUrl));

        Association latest = null;
        if (handleMap != null) {
            removeExpired(handleMap);
            for (String handle : handleMap.keySet()) {
                Association association = handleMap.get(handle);
                if (latest == null || latest.getExpiry().before(association.getExpiry()))
                    latest = association;
            }
        }
        return latest;
    }

    @Override
    public synchronized void remove(String opUrl, String handle) {
        @SuppressWarnings("unchecked")
        Map<String, Association> handleMap = (Map<String, Association>) memcachedClient.get(getKey(opUrl));

        if (handleMap != null) {
            removeExpired(handleMap);
            logger.debug("Removing association: " + handle + " widh OP: " + opUrl);
            handleMap.remove(handle);
            memcachedClient.put(getKey(opUrl), handleMap, true);
        }
    }

    private static void removeExpired(Map<String, Association> handleMap) {
        Set<String> handlesToRemove = new HashSet<String>();
        for (String handle : handleMap.keySet()) {
            Association association = handleMap.get(handle);
            if (association.hasExpired())
                handlesToRemove.add(handle);
        }

        for (String handle : handlesToRemove)
            handleMap.remove(handle);
    }

    private static String getKey(String opUrl) {
        return KEY_PREFIX + opUrl;
    }
}
