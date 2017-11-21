package com.accenturefederal.cio.azureadfilter;

import com.google.api.client.auth.oauth2.AuthorizationCodeRequestUrl;
import com.google.api.client.auth.oauth2.AuthorizationCodeResponseUrl;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;

public class azureAdFilter implements Filter {

    public static final String CLIENT_ID = "clientId";
    public static final String CLIENT_SECRET = "clientSecret";
    public static final String OAUTH2_URL = "oauth2url";
    public static final String REDIRECT_URL = "redirectUrl";
    public static final String LOGIN_URL = "loginUrl";

    protected String sessionVariableName = "oauth2login";

    protected String clientId = null;
    protected String clientSecret = null;
    protected String oauth2Url = "https://login.microsoftonline.com/common/oauth2/v2.0/authorize";
    protected String redirectUrl = null;
    protected String loginUrl = "/";

    public void init(FilterConfig filterConfig) throws ServletException {
        // TODO: collect client ID, client secret, oauth2 URL, redirect URL, session variable name to track login status
        this.clientId = filterConfig.getInitParameter(CLIENT_ID);
        this.clientSecret = filterConfig.getInitParameter(CLIENT_SECRET);
        this.redirectUrl = filterConfig.getInitParameter(REDIRECT_URL);
        if((filterConfig.getInitParameter(OAUTH2_URL)!=null)&&(!filterConfig.getInitParameter(OAUTH2_URL).isEmpty())){
            this.oauth2Url = filterConfig.getInitParameter(OAUTH2_URL);
        };
        if((filterConfig.getInitParameter(LOGIN_URL)!=null)&&(!filterConfig.getInitParameter(LOGIN_URL).isEmpty())){
            this.loginUrl = filterConfig.getInitParameter(LOGIN_URL);
        }
    }

    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
        HttpServletRequest request = (HttpServletRequest)servletRequest;
        String fullUrl = request.getRequestURL().toString()+'?'+request.getQueryString();
        if(request.getRequestURL().toString().equals(this.redirectUrl)) {
            // if this is the redirect URL, extract token, validate, and collect group membership from graph API.
            AuthorizationCodeResponseUrl authResponse =
                    new AuthorizationCodeResponseUrl(fullUrl);
            // check for user-denied error
            if (authResponse.getError() != null) {
                // authorization denied...
                ((HttpServletResponse)servletResponse).sendError(404);
            } else {
                // request access token using authResponse.getCode()...
                String code = authResponse.getCode();
                // Then - If successful, set logged in status in session and continue.
                request.getSession().setAttribute(sessionVariableName,code);
                request.getRequestDispatcher(loginUrl).forward(servletRequest,servletResponse);
            }
        } else if ((request.getSession().getAttribute(sessionVariableName) == null)
                ||(((String)(request.getSession().getAttribute(sessionVariableName))).isEmpty())) {
            // if not logged in, redirect to oauth2 provider
            Collection<String> responseTypes = new ArrayList<>();
            responseTypes.add("code");
            Collection<String> scopes = new ArrayList<>();
            scopes.addAll(Arrays.asList(new String[]{"openid","profile","https://graph.microsoft.com/Directory.AccessAsUser.All"}));
            // TODO: setState() a random value, stash in session and compare on entry
            String url =
                    new AuthorizationCodeRequestUrl(this.oauth2Url, clientId).setResponseTypes(responseTypes)
                            .setScopes(scopes)
                            .setState("xyz").setRedirectUri(this.redirectUrl).build();
            ((HttpServletResponse)servletResponse).sendRedirect(url);
        } else {
            // TODO: if logged in, verify access token still valid
        }
    }

    public void destroy() {

    }
}
