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

import java.util.Date;

import org.openid4java.consumer.AbstractNonceVerifier;

import com.zimbra.common.util.memcached.ZimbraMemcachedClient;
import com.zimbra.cs.util.Zimbra;

/**
 */
public class MemcachedNonceVerifier extends AbstractNonceVerifier {

    private static final String KEY_PREFIX = "zmOpenidConsumerNonce:";
    private ZimbraMemcachedClient memcachedClient = Zimbra.getAppContext().getBean(ZimbraMemcachedClient.class);

    public MemcachedNonceVerifier(int maxAgeSecs) {
        super(maxAgeSecs);
    }

    /**
     * Subclasses should implement this method and check if the nonce was seen before.
     * The nonce timestamp was verified at this point, it is valid and it is in the max age boudary.
     *
     * @param now The timestamp used to check the max age boudary.
     */
    @Override
    protected int seen(Date now, String opUrl, String nonce) {
        if (opUrl.equals(memcachedClient.get(KEY_PREFIX + nonce)))
            return SEEN;
        memcachedClient.put(KEY_PREFIX + nonce, opUrl, false);
        return OK;
    }
}
