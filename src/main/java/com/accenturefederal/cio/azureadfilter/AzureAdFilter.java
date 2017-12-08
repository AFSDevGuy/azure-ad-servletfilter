package com.accenturefederal.cio.azureadfilter;

import com.accenturefederal.cio.adal4j.AuthHelper;
import com.accenturefederal.cio.adal4j.HttpClientHelper;
import com.microsoft.aad.adal4j.AuthenticationResult;
import org.json.JSONArray;
import org.json.JSONObject;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;

public class AzureAdFilter implements Filter {

    public static final String REDIRECT_URL = "redirect_uri";
    public static final String LOGIN_URL = "login_uri";
    public static final String GROUPS = "groups";

    protected String redirectUrl = null;
    protected String loginUrl = "/";

    public void init(FilterConfig filterConfig) throws ServletException {
        this.redirectUrl = filterConfig.getServletContext().getInitParameter(REDIRECT_URL);
        if((filterConfig.getInitParameter(LOGIN_URL)!=null)&&(!filterConfig.getInitParameter(LOGIN_URL).isEmpty())){
            this.loginUrl = filterConfig.getInitParameter(LOGIN_URL);
        }
    }

    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain)
            throws IOException, ServletException {
        HttpServletRequest request = (HttpServletRequest)servletRequest;
        // validate that we are logged in
        if (!AuthHelper.isAuthenticated(request)) {
            error(servletResponse,404,"Unauthorized", "Request not authenticated");
        }
        // Attach username to request
        request = attachUsername(request);
        // Attach group memberships to request
        try {
            if(request.getSession().getAttribute(GROUPS)==null) {
                AuthenticationResult authResult = AuthHelper.getAuthSessionObject(request);
                Collection<String> groups = getGroupsFromGraph(authResult.getAccessToken());
                request.getSession().setAttribute(GROUPS,groups);
            }
            request = attachGroups(request,(Collection<String>)(request.getSession().getAttribute(GROUPS)));
        } catch (Exception e) {
            error(servletResponse,401, "Unauthorized", "Can't read group membership: "+e.getLocalizedMessage());
        }
        String fullUrl = request.getRequestURL().toString()+(request.getQueryString()==null?"":'?'+request.getQueryString());
        if(fullUrl.equals(this.redirectUrl)) {
            ((HttpServletResponse)servletResponse).sendRedirect(loginUrl);
        } else {
            filterChain.doFilter(request,servletResponse);
        }
    }

    private HttpServletRequest attachGroups(HttpServletRequest request, Collection<String> groups) throws Exception {
        request = addRequestHeader(request, "X-Groupname", groups);
        return request;
    }

    private Collection<String> getGroupsFromGraph(String accessToken) throws Exception {
        URL url = new URL("https://graph.windows.net/me/getMemberGroups?api-version=1.6");

        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        // Set the appropriate header fields in the request header.
        conn.setRequestProperty("Authorization", accessToken);
        conn.setRequestProperty("Accept", "application/json;");
        conn.setRequestProperty("Content-Type", "application/json");
        conn.setRequestMethod("POST");
        conn.setDoOutput(true);
        conn.getOutputStream().write("{\"securityEnabledOnly\":\"true\"}".getBytes());
        conn.getOutputStream().close();
        int responseCode = conn.getResponseCode();
        if (responseCode != 200) {
            String failureMsg = HttpClientHelper.getResponseStringFromConn(conn, false);
            throw new Exception(failureMsg);
        }
        String goodRespStr = HttpClientHelper.getResponseStringFromConn(conn, true);

        JSONObject response = HttpClientHelper.processGoodRespStr(responseCode, goodRespStr);
        JSONArray groups = response.getJSONObject("responseMsg").getJSONArray("value");
        Collection<String> groupNames = new ArrayList<>();
        for (int index=0; index<groups.length();index++) {
            String groupId = groups.getString(index);
            String groupName = getGroupNameFromGraph(accessToken, groupId);
            groupNames.add(groupName);
        }
        return groupNames;
    }

    private String getGroupNameFromGraph(String accessToken, String groupId) throws Exception {
        URL url = new URL("https://graph.windows.net/myorganization/groups/"+groupId+"?api-version=1.6");

        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        // Set the appropriate header fields in the request header.
        conn.setRequestProperty("Authorization", accessToken);
        conn.setRequestProperty("Accept", "application/json;");
        conn.setRequestProperty("Content-Type", "application/json");
        conn.setRequestMethod("GET");
        int responseCode = conn.getResponseCode();
        if (responseCode != 200) {
            String failureMsg = HttpClientHelper.getResponseStringFromConn(conn, false);
            throw new Exception(failureMsg);
        }
        String goodRespStr = HttpClientHelper.getResponseStringFromConn(conn, true);

        JSONObject response = HttpClientHelper.processGoodRespStr(responseCode, goodRespStr);
        return response.getJSONObject("responseMsg").getString("displayName");
    }

    private HttpServletRequest attachUsername(HttpServletRequest request) {
        AuthenticationResult authResult = AuthHelper.getAuthSessionObject(request);
        String username = authResult.getUserInfo().getDisplayableId();
        request = addRequestHeader(request, "X-Username",username);
        return request;
    }

    private HttpServletRequest addRequestHeader(HttpServletRequest request, String headerName, Collection<String> values) {
        for (String value : values) {
            request = addRequestHeader(request, headerName, value);
        }
        return request;
    }
    private HttpServletRequest addRequestHeader(HttpServletRequest request, String headerName, String value) {
        if (!(request instanceof HeaderMapRequestWrapper)) {
            request = new HeaderMapRequestWrapper(request);
        }
        String sourceHeader = request.getHeader(headerName);

        if ((sourceHeader==null)||(sourceHeader.isEmpty())) {
            sourceHeader = value;
        } else {
            sourceHeader = sourceHeader+','+value;
        }
        ((HeaderMapRequestWrapper)request).addHeader(headerName,sourceHeader);
        return request;
    }

    protected void error(ServletResponse servletResponse, int statusCode, String message, String logMessage)
            throws IOException {
        if ((message==null)||(message.isEmpty())) {
            ((HttpServletResponse)servletResponse).sendError(statusCode);
        } else {
            ((HttpServletResponse)servletResponse).sendError(statusCode,message);
        }
    }


    public void destroy() {

    }

}
