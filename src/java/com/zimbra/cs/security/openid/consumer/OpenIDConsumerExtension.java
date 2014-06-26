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

import com.zimbra.common.service.ServiceException;
import com.zimbra.cs.extension.ExtensionDispatcherServlet;
import com.zimbra.cs.extension.ZimbraExtension;

/**
 */
public class OpenIDConsumerExtension implements ZimbraExtension {

    /**
     * Defines a name for the extension. It must be an identifier.
     *
     * @return extension name
     */
    public String getName() {
        return "openidconsumer";
    }

    /**
     * Initializes the extension. Called when the extension is loaded.
     *
     * @throws com.zimbra.common.service.ServiceException
     *
     */
    public void init() throws ServiceException {
        ExtensionDispatcherServlet.register(this, new OpenIDConsumerHandler());
    }

    /**
     * Terminates the extension. Called when the server is shut down.
     */
    public void destroy() {
        ExtensionDispatcherServlet.unregister(this);
    }
}
