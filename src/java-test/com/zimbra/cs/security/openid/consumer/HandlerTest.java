package com.zimbra.cs.security.openid.consumer;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.net.URL;
import java.util.HashSet;
import java.util.Set;

import org.junit.Test;
import org.openid4java.discovery.DiscoveryInformation;
import org.openid4java.discovery.UrlIdentifier;
import org.openid4java.discovery.XriIdentifier;

public class HandlerTest {

    /*
     * Example of serialized open ID for Yahoo.com {"discoveryTypes":[
     * "http://www.idmanagement.gov/schema/2009/05/icam/no-pii.pdf",
     * "http://specs.openid.net/extensions/ui/1.0/lang-pref",
     * "http://specs.openid.net/extensions/pape/1.0",
     * "http://openid.net/srv/ax/1.0",
     * "http://www.idmanagement.gov/schema/2009/05/icam/openid-trust-level1.pdf"
     * ,
     * "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/privatepersonalidentifier"
     * , "http://specs.openid.net/auth/2.0/server",
     * "http://specs.openid.net/extensions/ui/1.0/mode/popup",
     * "http://csrc.nist.gov/publications/nistpubs/800-63/SP800-63V1_0_2.pdf",
     * "http://specs.openid.net/extensions/oauth/1.0" ],
     * "opEndpoint":"https://open.login.yahooapis.com/openid/op/auth",
     * "hasDelegateIdentifier":false,
     * "version":"http://specs.openid.net/auth/2.0/server" }
     */
    @Test
    public void testSerializeYahoo() throws Exception {
        DiscoveryInformation discInfo = new DiscoveryInformation(new URL(
                "https://open.login.yahooapis.com/openid/op/auth"), new UrlIdentifier("http://my.yahoo.com/myyahooid"),
                null, "http://specs.openid.net/auth/2.0/server", DiscoveryInformation.OPENID_TYPES);

        String serializedInfo = OpenIDConsumerHandler.serialize(discInfo);
        String expected = "eyJjbGFpbWVkSUQiOnsiaWRlbnRpZmllciI6Imh0dHA6Ly9teS55YWhvby5jb20vbXl5YWhvb2lkIiwiaWRUeXBlIjoiVVJMIn0sImRpc2NvdmVyeVR5cGVzIjpbImh0dHA6Ly9zcGVjcy5vcGVuaWQubmV0L2F1dGgvMi4wL3JldHVybl90byIsImh0dHA6Ly9vcGVuaWQubmV0L3NpZ25vbi8xLjEiLCJodHRwOi8vc3BlY3Mub3BlbmlkLm5ldC9hdXRoLzIuMC9zaWdub24iLCJodHRwOi8vb3BlbmlkLm5ldC9zaWdub24vMS4wIiwiaHR0cDovL3NwZWNzLm9wZW5pZC5uZXQvYXV0aC8yLjAvc2VydmVyIl0sIm9wRW5kcG9pbnQiOiJodHRwczovL29wZW4ubG9naW4ueWFob29hcGlzLmNvbS9vcGVuaWQvb3AvYXV0aCIsImhhc0RlbGVnYXRlSWRlbnRpZmllciI6ZmFsc2UsInZlcnNpb24iOiJodHRwOi8vc3BlY3Mub3BlbmlkLm5ldC9hdXRoLzIuMC9zZXJ2ZXIifQ==";
        assertEquals("Serialized string does not match the expected string", expected, serializedInfo);
    }

    @Test
    public void testDeSerializeYahoo() throws Exception {
        String serializedInfo = "eyJjbGFpbWVkSUQiOnsiaWRlbnRpZmllciI6Imh0dHA6Ly9teS55YWhvby5jb20vbXl5YWhvb2lkIiwiaWRUeXBlIjoiVVJMIn0sImRpc2NvdmVyeVR5cGVzIjpbImh0dHA6Ly9zcGVjcy5vcGVuaWQubmV0L2F1dGgvMi4wL3JldHVybl90byIsImh0dHA6Ly9vcGVuaWQubmV0L3NpZ25vbi8xLjEiLCJodHRwOi8vc3BlY3Mub3BlbmlkLm5ldC9hdXRoLzIuMC9zaWdub24iLCJodHRwOi8vb3BlbmlkLm5ldC9zaWdub24vMS4wIiwiaHR0cDovL3NwZWNzLm9wZW5pZC5uZXQvYXV0aC8yLjAvc2VydmVyIl0sIm9wRW5kcG9pbnQiOiJodHRwczovL29wZW4ubG9naW4ueWFob29hcGlzLmNvbS9vcGVuaWQvb3AvYXV0aCIsImhhc0RlbGVnYXRlSWRlbnRpZmllciI6ZmFsc2UsInZlcnNpb24iOiJodHRwOi8vc3BlY3Mub3BlbmlkLm5ldC9hdXRoLzIuMC9zZXJ2ZXIifQ==";
        DiscoveryInformation discInfo = OpenIDConsumerHandler.deserializeDiscoveryInfo(serializedInfo);
        assertNotNull("deserialization produced a null object", discInfo);
        assertNotNull("getClaimedIdentifier() should return a non null object", discInfo.getClaimedIdentifier());
        assertTrue("claimed ID should be an URL ID", discInfo.getClaimedIdentifier() instanceof UrlIdentifier);
        assertEquals("claimed identifier does not match", "http://my.yahoo.com/myyahooid", discInfo
                .getClaimedIdentifier().getIdentifier());
        assertNotNull("openID types should not be empty", discInfo.getTypes());
        assertEquals("wrong number of openid types", DiscoveryInformation.OPENID_TYPES.size(), discInfo.getTypes()
                .size());
        assertTrue("deserialized DisoveryInformation should have a claimed identifier", discInfo.hasClaimedIdentifier());
        assertFalse("deserialized DisoveryInformation should not have a delegated identifier",
                discInfo.hasDelegateIdentifier());
        assertEquals("end point URL does not match", "https://open.login.yahooapis.com/openid/op/auth", discInfo
                .getOPEndpoint().toString());
        assertEquals("version info does not match", "http://specs.openid.net/auth/2.0/server", discInfo.getVersion());
    }

    /*
     * Example of serialized Open ID for Livejournal {"claimedID":
     * {"identifier":"http://grishick.livejournal.com/","idType":"URL"},
     * "discoveryTypes":["http://specs.openid.net/auth/2.0/signon"],
     * "opEndpoint":"http://www.livejournal.com/openid/server.bml",
     * "hasDelegateIdentifier":true,
     * "version":"http://specs.openid.net/auth/2.0/signon",
     * "delegateIdentifier":"http://grishick.livejournal.com/" }
     */

    @Test
    public void testSerializeLJ() throws Exception {
        Set<String> discoveryTypes = new HashSet<String>();
        discoveryTypes.add(DiscoveryInformation.OPENID2);

        DiscoveryInformation discInfo = new DiscoveryInformation(
                new URL("http://www.livejournal.com/openid/server.bml"), new UrlIdentifier(
                        "http://grishick.livejournal.com/"), "http://grishick.livejournal.com/",
                "http://specs.openid.net/auth/2.0/signon", discoveryTypes);

        String serializedInfo = OpenIDConsumerHandler.serialize(discInfo);
        String expected = "eyJjbGFpbWVkSUQiOnsiaWRlbnRpZmllciI6Imh0dHA6Ly9ncmlzaGljay5saXZlam91cm5hbC5jb20vIiwiaWRUeXBlIjoiVVJMIn0sImRpc2NvdmVyeVR5cGVzIjpbImh0dHA6Ly9zcGVjcy5vcGVuaWQubmV0L2F1dGgvMi4wL3NpZ25vbiJdLCJvcEVuZHBvaW50IjoiaHR0cDovL3d3dy5saXZlam91cm5hbC5jb20vb3BlbmlkL3NlcnZlci5ibWwiLCJoYXNEZWxlZ2F0ZUlkZW50aWZpZXIiOnRydWUsInZlcnNpb24iOiJodHRwOi8vc3BlY3Mub3BlbmlkLm5ldC9hdXRoLzIuMC9zaWdub24iLCJkZWxlZ2F0ZUlkZW50aWZpZXIiOiJodHRwOi8vZ3Jpc2hpY2subGl2ZWpvdXJuYWwuY29tLyJ9";
        assertEquals("Serialized string does not match the expected string", expected, serializedInfo);
    }

    @Test
    public void testDeSerializeLJ() throws Exception {
        String serializedInfo = "eyJjbGFpbWVkSUQiOnsiaWRlbnRpZmllciI6Imh0dHA6Ly9ncmlzaGljay5saXZlam91cm5hbC5jb20vIiwiaWRUeXBlIjoiVVJMIn0sImRpc2NvdmVyeVR5cGVzIjpbImh0dHA6Ly9zcGVjcy5vcGVuaWQubmV0L2F1dGgvMi4wL3NpZ25vbiJdLCJvcEVuZHBvaW50IjoiaHR0cDovL3d3dy5saXZlam91cm5hbC5jb20vb3BlbmlkL3NlcnZlci5ibWwiLCJoYXNEZWxlZ2F0ZUlkZW50aWZpZXIiOnRydWUsInZlcnNpb24iOiJodHRwOi8vc3BlY3Mub3BlbmlkLm5ldC9hdXRoLzIuMC9zaWdub24iLCJkZWxlZ2F0ZUlkZW50aWZpZXIiOiJodHRwOi8vZ3Jpc2hpY2subGl2ZWpvdXJuYWwuY29tLyJ9";
        DiscoveryInformation discInfo = OpenIDConsumerHandler.deserializeDiscoveryInfo(serializedInfo);
        assertNotNull("deserialization produced a null object", discInfo);
        assertNotNull("getClaimedIdentifier() should return a non null object", discInfo.getClaimedIdentifier());
        assertTrue("claimed ID should be an URL ID", discInfo.getClaimedIdentifier() instanceof UrlIdentifier);
        assertEquals("claimed identifier does not match", "http://grishick.livejournal.com/", discInfo
                .getClaimedIdentifier().getIdentifier());
        assertNotNull("openID types should not be empty", discInfo.getTypes());
        assertEquals("wrong number of openid types", 1, discInfo.getTypes().size());
        assertEquals("wrong discovery type", DiscoveryInformation.OPENID2, discInfo.getTypes().iterator().next()
                .toString());
        assertTrue("deserialized DisoveryInformation should have a claimed identifier", discInfo.hasClaimedIdentifier());
        assertTrue("deserialized DisoveryInformation should have a delegated identifier",
                discInfo.hasDelegateIdentifier());
        assertEquals("Delegate ID does not match", "http://grishick.livejournal.com/", discInfo.getDelegateIdentifier());
        assertEquals("end point URL does not match", "http://www.livejournal.com/openid/server.bml", discInfo
                .getOPEndpoint().toString());
        assertEquals("version info does not match", "http://specs.openid.net/auth/2.0/signon", discInfo.getVersion());
    }

    @Test
    public void testSerializeXRIIdentifier() throws Exception {
        Set<String> discoveryTypes = new HashSet<String>();
        discoveryTypes.add(DiscoveryInformation.OPENID2);
        XriIdentifier identifier = new XriIdentifier("http://widgeterian.wordpress.com",
                "http://widgeterian.wordpress.com", "http://widgeterian.wordpress.com");

        DiscoveryInformation discInfo = new DiscoveryInformation(new URL("http://www.wordpress.com/openid/server.bml"),
                identifier, "http://widgeterian.wordpress.com", "http://specs.openid.net/auth/2.0/signon",
                discoveryTypes);

        String serializedInfo = OpenIDConsumerHandler.serialize(discInfo);
        String expected = "eyJjbGFpbWVkSUQiOnsiaWRlbnRpZmllciI6Imh0dHA6Ly93aWRnZXRlcmlhbi53b3JkcHJlc3MuY29tIiwiaXJpTm9ybWFsRm9ybSI6Imh0dHA6Ly93aWRnZXRlcmlhbi53b3JkcHJlc3MuY29tIiwiaWRUeXBlIjoiWFJJIiwidXJpTm9ybWFsRm9ybSI6Imh0dHA6Ly93aWRnZXRlcmlhbi53b3JkcHJlc3MuY29tIn0sImRpc2NvdmVyeVR5cGVzIjpbImh0dHA6Ly9zcGVjcy5vcGVuaWQubmV0L2F1dGgvMi4wL3NpZ25vbiJdLCJvcEVuZHBvaW50IjoiaHR0cDovL3d3dy53b3JkcHJlc3MuY29tL29wZW5pZC9zZXJ2ZXIuYm1sIiwiaGFzRGVsZWdhdGVJZGVudGlmaWVyIjp0cnVlLCJ2ZXJzaW9uIjoiaHR0cDovL3NwZWNzLm9wZW5pZC5uZXQvYXV0aC8yLjAvc2lnbm9uIiwiZGVsZWdhdGVJZGVudGlmaWVyIjoiaHR0cDovL3dpZGdldGVyaWFuLndvcmRwcmVzcy5jb20ifQ==";
        assertEquals("Serialized string does not match the expected string", expected, serializedInfo);
    }

    @Test
    public void testDeSerializeXRI() throws Exception {
        String serializedInfo = "eyJjbGFpbWVkSUQiOnsiaWRlbnRpZmllciI6Imh0dHA6Ly93aWRnZXRlcmlhbi53b3JkcHJlc3MuY29tIiwiaXJpTm9ybWFsRm9ybSI6Imh0dHA6Ly93aWRnZXRlcmlhbi53b3JkcHJlc3MuY29tIiwiaWRUeXBlIjoiWFJJIiwidXJpTm9ybWFsRm9ybSI6Imh0dHA6Ly93aWRnZXRlcmlhbi53b3JkcHJlc3MuY29tIn0sImRpc2NvdmVyeVR5cGVzIjpbImh0dHA6Ly9zcGVjcy5vcGVuaWQubmV0L2F1dGgvMi4wL3NpZ25vbiJdLCJvcEVuZHBvaW50IjoiaHR0cDovL3d3dy53b3JkcHJlc3MuY29tL29wZW5pZC9zZXJ2ZXIuYm1sIiwiaGFzRGVsZWdhdGVJZGVudGlmaWVyIjp0cnVlLCJ2ZXJzaW9uIjoiaHR0cDovL3NwZWNzLm9wZW5pZC5uZXQvYXV0aC8yLjAvc2lnbm9uIiwiZGVsZWdhdGVJZGVudGlmaWVyIjoiaHR0cDovL3dpZGdldGVyaWFuLndvcmRwcmVzcy5jb20ifQ==";
        DiscoveryInformation discInfo = OpenIDConsumerHandler.deserializeDiscoveryInfo(serializedInfo);
        assertNotNull("deserialization produced a null object", discInfo);
        assertNotNull("getClaimedIdentifier() should return a non null object", discInfo.getClaimedIdentifier());
        assertTrue("claimed ID should be an XRI ID", discInfo.getClaimedIdentifier() instanceof XriIdentifier);
        assertEquals("claimed identifier does not match", "http://widgeterian.wordpress.com", discInfo
                .getClaimedIdentifier().getIdentifier());
        assertNotNull("openID types should not be empty", discInfo.getTypes());
        assertEquals("wrong number of openid types", 1, discInfo.getTypes().size());
        assertEquals("wrong discovery type", DiscoveryInformation.OPENID2, discInfo.getTypes().iterator().next()
                .toString());
        assertTrue("deserialized DisoveryInformation should have a claimed identifier", discInfo.hasClaimedIdentifier());
        assertTrue("deserialized DisoveryInformation should have a delegated identifier",
                discInfo.hasDelegateIdentifier());
        assertEquals("Delegate ID does not match", "http://widgeterian.wordpress.com", discInfo.getDelegateIdentifier());
        assertEquals("end point URL does not match", "http://www.wordpress.com/openid/server.bml", discInfo
                .getOPEndpoint().toString());
        assertEquals("version info does not match", "http://specs.openid.net/auth/2.0/signon", discInfo.getVersion());
    }
}
