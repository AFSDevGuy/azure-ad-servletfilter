package com.accenturefederal.cio.azureadfilter;

import com.google.api.client.auth.oauth2.AuthorizationCodeRequestUrl;

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

    protected String sessionVariableName = "oauth2login";

    protected String clientId = null;
    protected String clientSecret = null;
    protected String oauth2Url = "https://login.microsoftonline.com/common/oauth2/v2.0/authorize";
    protected String redirectUrl = null;

    public void init(FilterConfig filterConfig) throws ServletException {
        // TODO: collect client ID, client secret, oauth2 URL, redirect URL, session variable name to track login status
        this.clientId = filterConfig.getInitParameter(CLIENT_ID);
        this.clientSecret = filterConfig.getInitParameter(CLIENT_SECRET);
        this.redirectUrl = filterConfig.getInitParameter(REDIRECT_URL);
        if((filterConfig.getInitParameter(OAUTH2_URL)!=null)&&(!filterConfig.getInitParameter(OAUTH2_URL).isEmpty())){
            this.oauth2Url = filterConfig.getInitParameter(OAUTH2_URL);
        };
    }

    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
        HttpServletRequest request = (HttpServletRequest)servletRequest;
        // TODO: if this is the redirect URL, extract token, validate, and collect group membership from graph API.
        // Then - If successful, set logged in status in session and continue.

        // if not logged in, redirect to oauth2 provider
        if ((request.getSession().getAttribute(sessionVariableName) == null)
                ||(((String)(request.getSession().getAttribute(sessionVariableName))).isEmpty())) {
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
        }
        // TODO: if logged in, verify access token still valid

    }

    public void destroy() {

    }
}
