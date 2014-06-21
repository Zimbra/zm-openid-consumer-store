<!--
 * ***** BEGIN LICENSE BLOCK *****
 * Zimbra Collaboration Suite Server
 * Copyright (C) 2011, 2013 Zimbra, Inc.
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
-->
<%--
  ~ Copyright 2006-2008 Sxip Identity Corporation
  --%>

<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN"
"http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
    <title>OpenID HTML FORM Redirection</title>
</head>
<body onload="document.forms['openid-form-redirection'].submit();">
    <form name="openid-form-redirection" action="${message.OPEndpoint}" method="post" accept-charset="utf-8">
        <c:forEach var="parameter" items="${message.parameterMap}">
        <input type="hidden" name="${parameter.key}" value="${parameter.value}"/>
        </c:forEach>
        <button type="submit">Continue...</button>
    </form>
</body>
</html>
