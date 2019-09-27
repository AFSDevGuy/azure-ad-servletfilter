package com.accenturefederal.cio.azureadfilter;

import com.accenturefederal.cio.adal4j.AuthHelper;
import com.accenturefederal.cio.adal4j.HttpClientHelper;
import com.microsoft.aad.adal4j.AuthenticationContext;
import com.microsoft.aad.adal4j.AuthenticationResult;
import com.microsoft.aad.adal4j.ClientCredential;
import org.json.JSONArray;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.ArrayList;
import java.util.Collection;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

public class AzureAdFilter implements Filter {

    public static final String REDIRECT_URL = "redirect_uri";
    public static final String LOGIN_URL = "login_uri";
    public static final String GROUPS = "groups";
    public static final String ALLOWED_DOMAINS = "allowed_domains";
    public static final String AUTHORITY = "authority";
    public static final String TENANT = "tenant";
    public static final String CLIENT_ID = "client_id";
    public static final String SECRET_KEY = "secret_key";

    protected String redirectUrl = null;
    protected String loginUrl = "/";
    protected String[] allowedDomains = new String[0];
    protected String context = "/";
    protected String authority = null;
    protected String tenant = null;
    protected String clientId = null;
    protected String secretKey = null;

    private final Logger log = LoggerFactory.getLogger(AzureAdFilter.class);

    public void init(FilterConfig filterConfig) throws ServletException {
        this.tenant = filterConfig.getServletContext().getInitParameter(TENANT);
        this.redirectUrl = filterConfig.getServletContext().getInitParameter(REDIRECT_URL);
        this.authority = filterConfig.getServletContext().getInitParameter(AUTHORITY);
        this.clientId = filterConfig.getServletContext().getInitParameter(CLIENT_ID);
        this.secretKey = filterConfig.getServletContext().getInitParameter(SECRET_KEY);
        if((filterConfig.getServletContext().getInitParameter(LOGIN_URL)!=null)&&(!filterConfig.getServletContext().getInitParameter(LOGIN_URL).isEmpty())){
            this.loginUrl = filterConfig.getServletContext().getInitParameter(LOGIN_URL);
        }
        if ((filterConfig.getServletContext().getInitParameter(ALLOWED_DOMAINS)!=null)&&(!filterConfig.getServletContext().getInitParameter(ALLOWED_DOMAINS).isEmpty())) {
            this.allowedDomains = filterConfig.getServletContext().getInitParameter(ALLOWED_DOMAINS).split(",");
            for(int index=0; index<allowedDomains.length; index++) {
                allowedDomains[index] = allowedDomains[index].trim();
            }
        }
        context = filterConfig.getServletContext().getContextPath();
        log.info("init: redirect_uri={} login_uri={} allowed_domains={} context={}",redirectUrl,loginUrl,allowedDomains, context);

    }

    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain)
            throws IOException, ServletException {
        HttpServletRequest request = (HttpServletRequest)servletRequest;
        // validate that we are logged in
        if (!AuthHelper.isAuthenticated(request)) {
            error(servletResponse,404,"Unauthorized", "Request not authenticated");
            return;
        }
        // Attach username to request
        request = attachUsername(request);
        if (!isAllowedDomain(request.getHeader("X-Username"))) {
            error(servletResponse,404,"Unauthorized", "Unauthorized domain access");
            return;
        }
        // Attach group memberships to request
        try {
            if(request.getSession().getAttribute(GROUPS)==null) {
                log.info("must find groups for user {}", AuthHelper.getAuthSessionObject(request).getUserInfo().getDisplayableId());
                AuthenticationResult authResult = AuthHelper.getAuthSessionObject(request);
                Collection<String> groups = getGroupsFromGraph(authResult);
                log.info("groups found for user {}: {}", AuthHelper.getAuthSessionObject(request).getUserInfo().getDisplayableId(), groups);
                request.getSession().setAttribute(GROUPS,groups);
            }
            request = attachGroups(request,(Collection<String>)(request.getSession().getAttribute(GROUPS)));
        } catch (Throwable e) {
            error(servletResponse,401, "Unauthorized", "Can't read group membership: "+e.getLocalizedMessage());
            return;
        }
        String fullUrl = request.getRequestURL().toString()+(request.getQueryString()==null?"":'?'+request.getQueryString());
        //((HttpServletResponse)servletResponse).setHeader("Access-Control-Allow-Origin", request.getHeader("Origin")==null?"*":request.getHeader("Origin"));
        //((HttpServletResponse)servletResponse).setHeader("Access-Control-Allow-Credentials", "true");
        //((HttpServletResponse)servletResponse).setHeader("Access-Control-Allow-Methods", "POST, GET");
        //((HttpServletResponse)servletResponse).setHeader("Access-Control-Max-Age", "3600");
        if(fullUrl.equals(this.redirectUrl)) {
            log.info("redirecting {} to {}", fullUrl, loginUrl);
            ((HttpServletResponse)servletResponse).sendRedirect(loginUrl);
        } else {
            filterChain.doFilter(request,servletResponse);
        }
    }

    private boolean isAllowedDomain(String username) {
        if ((allowedDomains==null)||(allowedDomains.length==0)){
            return true;
        }
        for (String allowedDomain : allowedDomains) {
            if(username.toLowerCase().endsWith("@"+allowedDomain.toLowerCase())) {
                return true;
            }
        }
        return false;
    }

    private HttpServletRequest attachGroups(HttpServletRequest request, Collection<String> groups) throws Exception {
        request = addRequestHeader(request, "X-Groupname", groups);
        return request;
    }

    private Collection<String> getGroupsFromGraph(AuthenticationResult authApplication) throws Throwable {
        AuthenticationContext context;
        AuthenticationResult authGraph = null;
        ExecutorService service = null;
        try {
            service = Executors.newFixedThreadPool(1);
            context = new AuthenticationContext(authority + tenant + "/", true,
                    service);
            ClientCredential credential = new ClientCredential(clientId,secretKey);
            Future<AuthenticationResult> future = context
                    .acquireTokenByRefreshToken(authApplication.getRefreshToken(),credential,"https://graph.windows.net/",null);
            authGraph = future.get();
        } catch (ExecutionException e) {
            throw e.getCause();
        } finally {
            service.shutdown();
        }
        URL url = new URL("https://graph.windows.net/me/memberOf?api-version=1.6");

        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        // Set the appropriate header fields in the request header.
        conn.setRequestProperty("Authorization", authGraph.getAccessToken());
        conn.setRequestProperty("Accept", "application/json;");
        conn.setRequestProperty("Content-Type", "application/json");
        conn.setRequestMethod("GET");
        //conn.setDoOutput(true);
        //conn.getOutputStream().write("{\"securityEnabledOnly\":\"true\"}".getBytes());
        //conn.getOutputStream().close();
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
            String groupName = ((JSONObject)groups.get(index)).getString("displayName");
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
        log.error("status code: {} message: {} logMessage: {}",statusCode, message, logMessage);
        if ((message==null)||(message.isEmpty())) {
            ((HttpServletResponse)servletResponse).sendError(statusCode);
        } else {
            ((HttpServletResponse)servletResponse).sendError(statusCode,message);
        }
    }


    public void destroy() {

    }

}
