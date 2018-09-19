package top.zpliu.sentry.proxy;

import org.apache.http.*;
import org.apache.http.client.HttpClient;
import org.apache.http.client.config.CookieSpecs;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.utils.URIUtils;
import org.apache.http.client.utils.URLEncodedUtils;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.InputStreamEntity;
import org.apache.http.entity.mime.MultipartEntityBuilder;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.message.*;
import org.apache.http.util.EntityUtils;
import org.eclipse.jetty.http.HttpHeader;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.multipart.MultipartHttpServletRequest;
import javax.annotation.PostConstruct;
import javax.annotation.PreDestroy;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.Closeable;
import java.io.IOException;
import java.io.OutputStream;
import java.net.HttpCookie;
import java.net.URI;
import java.util.*;

@Service
public class ProxyClient {
    public static String HTTP_URL_SPLIT_1 = "://";
    public static String HTTP_URL_SPLIT_2 = ":";
    public static String HTTP_URL_SPLIT_3 = "/";
    public static String HTTP_URL_SPLIT_4 = "?";

    @Value("${proxy.target-url}")
    private String targetUri;

    @Value("${proxy.connect-timeout:-1}")
    private int connectTimeout;

    @Value("${proxy.socket-timeout:-1}")
    private int readTimeout;

    private String proxyUri;
    private CloseableHttpClient httpClient;
    private URI targetUriObj;
    private HttpHost targetHost;
    @PostConstruct
    public void init() throws ServletException {
        initTarget();
        getHttpClient();
    }

    @PreDestroy
    public void destory(){
        if (httpClient instanceof Closeable) {
            try {
                ((Closeable) httpClient).close();
            } catch (IOException e) {
                System.out.println("While destroying servlet, shutting down HttpClient");
            }
        } else {
            //Older releases require we do this:
            if (httpClient != null)
                httpClient.getConnectionManager().shutdown();
        }
    }
    protected void initTarget() throws ServletException {
        if (targetUri == null){
            throw new ServletException("proxy.target-url is required.");
        }
        try {
            targetUriObj = new URI(targetUri);
        } catch (Exception e) {
            throw new ServletException("Trying to process targetUri init parameter: "+e,e);
        }
        targetHost = URIUtils.extractHost(targetUriObj);

    }

    public void go(HttpServletRequest servletRequest, HttpServletResponse servletResponse) throws IOException, ServletException {
        String method = servletRequest.getMethod();
        String proxyRequestUri =  rewriteRequestUrl(servletRequest);

        HttpResponse proxyResponse = null;
        try {
            HttpRequest proxyRequest;
            if (servletRequest.getHeader(HttpHeaders.CONTENT_LENGTH) != null || servletRequest.getHeader(HttpHeaders.TRANSFER_ENCODING) != null) {
                proxyRequest = newProxyRequestWithEntity(method, proxyRequestUri, servletRequest);
            } else {
                proxyRequest = new BasicHttpRequest(method, proxyRequestUri);
            }
            copyRequestHeaders(servletRequest, proxyRequest);
            proxyResponse = doExecute(servletRequest, servletResponse, proxyRequest);
            int statusCode = proxyResponse.getStatusLine().getStatusCode();
            servletResponse.setStatus(statusCode, proxyResponse.getStatusLine().getReasonPhrase());
            copyResponseHeaders(proxyResponse, servletRequest, servletResponse);

            if (statusCode == HttpServletResponse.SC_NOT_MODIFIED) {
                servletResponse.setIntHeader(HttpHeaders.CONTENT_LENGTH, 0);
            } else {
                copyResponseEntity(proxyResponse, servletResponse, proxyRequest, servletRequest);
            }

        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            //关闭流
            if (proxyResponse != null){
                EntityUtils.consumeQuietly(proxyResponse.getEntity());
            }

        }
    }

    protected HttpResponse doExecute(HttpServletRequest servletRequest, HttpServletResponse servletResponse,
                                     HttpRequest proxyRequest) throws IOException {
        return getHttpClient().execute(targetHost, proxyRequest);
    }

    private HttpRequest newProxyRequestWithEntity(String method, String proxyRequestUri,HttpServletRequest servletRequest) throws IOException, ServletException {
        HttpEntityEnclosingRequest eProxyRequest = new BasicHttpEntityEnclosingRequest(method, proxyRequestUri);
        if(servletRequest.getContentType().contains("multipart/form-data")){
            eProxyRequest.setEntity(newProxyRequestWithEntityForMultipart(servletRequest));
        }else if(servletRequest.getContentType().contains("application/x-www-form-urlencoded")){
            eProxyRequest.setEntity(newProxyRequestWithEntityForFormUrlencoded(servletRequest));
        }else{
            eProxyRequest.setEntity(new InputStreamEntity(servletRequest.getInputStream(), getContentLength(servletRequest)));
        }
        return eProxyRequest;

    }
    protected HttpEntity newProxyRequestWithEntityForMultipart(HttpServletRequest servletRequest) throws IOException, ServletException {
        MultipartEntityBuilder multipartEntityBuilder = MultipartEntityBuilder.create();
        MultipartHttpServletRequest mRequest = (MultipartHttpServletRequest)servletRequest;
        MultiValueMap<String, MultipartFile> parts = mRequest.getMultiFileMap();
        Map<String, String[]> params = mRequest.getParameterMap();
        for (String s : params.keySet()) {
            for (String s1 : params.get(s)) {
                multipartEntityBuilder.addTextBody(s,s1, ContentType.TEXT_PLAIN.withCharset("UTF-8"));
            }
        }
        for (String s : parts.keySet()) {
            List<MultipartFile> multipartFiles =  parts.get(s);
            for (MultipartFile multipartFile : multipartFiles) {
                multipartEntityBuilder.addBinaryBody(multipartFile.getName(),multipartFile.getBytes());
            }
        }
        return multipartEntityBuilder.build();
    }
    protected UrlEncodedFormEntity newProxyRequestWithEntityForFormUrlencoded(HttpServletRequest servletRequest) throws IOException {
        List<NameValuePair> queryParams = Collections.emptyList();
        String queryString = servletRequest.getQueryString();
        if (queryString != null) {
            queryParams = URLEncodedUtils.parse(queryString, Consts.UTF_8);
        }

        Map<String, String[]> form = servletRequest.getParameterMap();
        List<NameValuePair> params = new ArrayList<NameValuePair>();
        OUTER_LOOP:
        for (Iterator<String> nameIterator = form.keySet().iterator(); nameIterator.hasNext(); ) {
            String name = nameIterator.next();
            // skip parameters from query string
            for (NameValuePair queryParam : queryParams) {
                if (name.equals(queryParam.getName())) {
                    continue OUTER_LOOP;
                }
            }
            String[] value = form.get(name);
            if (value.length != 1) {
                throw new RuntimeException("expecting one value in post form");
            }
            params.add(new BasicNameValuePair(name, value[0]));
        }

        return new UrlEncodedFormEntity(params, "UTF-8");
    }

    protected static final HeaderGroup hopByHopHeaders;
    static {
        hopByHopHeaders = new HeaderGroup();
        String[] headers = new String[] {
                "Connection",
                "Keep-Alive",
                "Proxy-Authenticate",
                "Proxy-Authorization",
                "TE",
                "Trailers",
                "Transfer-Encoding",
                "Upgrade"
        };
        for (String header : headers) {
            hopByHopHeaders.addHeader(new BasicHeader(header, null));
        }
    }
    protected void copyRequestHeaders2(HttpServletRequest clientRequest, HttpRequest proxyRequest)
    {
        for (Header header : proxyRequest.getAllHeaders()) {
            System.out.println(header.getName() + " : " + header.getValue());
        }
        Set<String> headersToRemove = findConnectionHeaders(clientRequest);

        for (Enumeration<String> headerNames = clientRequest.getHeaderNames(); headerNames.hasMoreElements();)
        {
            String headerName = headerNames.nextElement();
            String lowerHeaderName = headerName.toLowerCase(Locale.ENGLISH);
            if (headerName.equalsIgnoreCase(HttpHeaders.CONTENT_LENGTH))
                continue;
            if (headerName.equalsIgnoreCase(HttpHeaders.HOST))
                continue;
            // Remove hop-by-hop headers.
            if (hopByHopHeaders.containsHeader(headerName))
                continue;
            if (headersToRemove != null && headersToRemove.contains(lowerHeaderName))
                continue;

            for (Enumeration<String> headerValues = clientRequest.getHeaders(headerName); headerValues.hasMoreElements();)
            {
                String headerValue = headerValues.nextElement();
                if (headerValue != null)
                    proxyRequest.addHeader(headerName, headerValue);

                System.out.println(headerName+" : " + headerValue);
            }
        }

    }
    protected Set<String> findConnectionHeaders(HttpServletRequest clientRequest)
    {
        // Any header listed by the Connection header must be removed:
        // http://tools.ietf.org/html/rfc7230#section-6.1.
        Set<String> hopHeaders = null;
        Enumeration<String> connectionHeaders = clientRequest.getHeaders(HttpHeader.CONNECTION.asString());
        while (connectionHeaders.hasMoreElements())
        {
            String value = connectionHeaders.nextElement();
            String[] values = value.split(",");
            for (String name : values)
            {
                name = name.trim().toLowerCase(Locale.ENGLISH);
                if (hopHeaders == null)
                    hopHeaders = new HashSet<>();
                hopHeaders.add(name);
            }
        }
        return hopHeaders;
    }
    protected void copyRequestHeaders(HttpServletRequest servletRequest, HttpRequest proxyRequest) {
        // Get an Enumeration of all of the header names sent by the client
        @SuppressWarnings("unchecked")
        Enumeration<String> enumerationOfHeaderNames = servletRequest.getHeaderNames();
        while (enumerationOfHeaderNames.hasMoreElements()) {
            String headerName = enumerationOfHeaderNames.nextElement();
            copyRequestHeader(servletRequest, proxyRequest, headerName);
        }
    }

    protected void copyRequestHeader(HttpServletRequest servletRequest, HttpRequest proxyRequest,
                                     String headerName) {
        //skip copy Content-Type:multipart/form-data;banner:==============
        if(headerName.equalsIgnoreCase(HttpHeaders.CONTENT_TYPE)){
            if(servletRequest.getHeader(headerName).contains("multipart")){
                return;
            }
        }
        if (headerName.equalsIgnoreCase(HttpHeaders.CONTENT_LENGTH))
            return;
        if (hopByHopHeaders.containsHeader(headerName))
            return;
        @SuppressWarnings("unchecked")
        Enumeration<String> headers = servletRequest.getHeaders(headerName);
        while (headers.hasMoreElements()) {
            String headerValue = headers.nextElement();
            proxyRequest.addHeader(headerName, headerValue);
        }
    }

    /** Copy proxied response headers back to the servlet client. */
    protected void copyResponseHeaders(HttpResponse proxyResponse, HttpServletRequest servletRequest,
                                       HttpServletResponse servletResponse) {
        for (Header header : proxyResponse.getAllHeaders()) {
            copyResponseHeader(servletRequest, servletResponse, header);
        }
    }

    protected void copyResponseHeader(HttpServletRequest servletRequest,
                                      HttpServletResponse servletResponse, Header header) {
        String headerName = header.getName();
        if (hopByHopHeaders.containsHeader(headerName))
            return;
        String headerValue = header.getValue();
        if (headerName.equalsIgnoreCase(org.apache.http.cookie.SM.SET_COOKIE) ||
                headerName.equalsIgnoreCase(org.apache.http.cookie.SM.SET_COOKIE2)) {
            copyProxyCookie(servletRequest, servletResponse, headerValue);
//        } else if (headerName.equalsIgnoreCase(HttpHeaders.LOCATION)) {
//            // LOCATION Header may have to be rewritten.
//            servletResponse.addHeader(headerName, rewriteResponseUrl(servletRequest, headerValue));
        } else {
            servletResponse.addHeader(headerName, headerValue);
        }
    }

    /**
     * Copy cookie from the proxy to the servlet client.
     * Replaces cookie path to local path and renames cookie to avoid collisions.
     */
    protected void copyProxyCookie(HttpServletRequest servletRequest,
                                   HttpServletResponse servletResponse, String headerValue) {
        //build path for resulting cookie
        String path = servletRequest.getContextPath(); // path starts with / or is empty string
        path += servletRequest.getServletPath(); // servlet path starts with / or is empty string
        if(path.isEmpty()){
            path = "/";
        }

        for (HttpCookie cookie : HttpCookie.parse(headerValue)) {
            //set cookie name prefixed w/ a proxy value so it won't collide w/ other cookies
            String proxyCookieName = cookie.getName();
            Cookie servletCookie = new Cookie(proxyCookieName, cookie.getValue());
            servletCookie.setComment(cookie.getComment());
            servletCookie.setMaxAge((int) cookie.getMaxAge());
            servletCookie.setPath(path); //set to the path of the proxy servlet
            // don't set cookie domain
            servletCookie.setSecure(cookie.getSecure());
            servletCookie.setVersion(cookie.getVersion());
            servletResponse.addCookie(servletCookie);
        }
    }

    protected void copyResponseEntity(HttpResponse proxyResponse, HttpServletResponse servletResponse,
                                      HttpRequest proxyRequest, HttpServletRequest servletRequest)
            throws IOException {
        HttpEntity entity = proxyResponse.getEntity();
        if (entity != null) {
            OutputStream servletOutputStream = servletResponse.getOutputStream();
            entity.writeTo(servletOutputStream);
        }
    }

    private long getContentLength(HttpServletRequest request) {
        String contentLengthHeader = request.getHeader("Content-Length");
        if (contentLengthHeader != null) {
            return Long.parseLong(contentLengthHeader);
        }
        return -1L;
    }


    public HttpClient getHttpClient(){
        if(httpClient == null){
            RequestConfig requestConfig = RequestConfig.custom()
                                            .setRedirectsEnabled(false)
                                            .setCookieSpec(CookieSpecs.IGNORE_COOKIES) // we handle them in the servlet instead
                                            .setConnectTimeout(connectTimeout)
                                            .setSocketTimeout(readTimeout)
                                            .build();
            HttpClientBuilder clientBuilder = HttpClientBuilder.create().setDefaultRequestConfig(requestConfig);
            httpClient =  clientBuilder.build();
        }
        return httpClient;
    }

    /**
     * rewriteRequestUrl
     * @param request
     * @return
     */
    private String rewriteRequestUrl(HttpServletRequest request) {
        StringBuffer url = new StringBuffer();
        url.append(targetUri);
        url.append(request.getServletPath());

        if(!StringUtils.isEmpty(request.getQueryString())){
            url.append(HTTP_URL_SPLIT_4);
            url.append(request.getQueryString());
        }

        return url.toString();
    }


    /**
     * rewriteResponseUrl
     * @param servletRequest
     * @param theUrl
     * @return
     */
    private String rewriteResponseUrl(HttpServletRequest servletRequest, String theUrl) {
        final String targetUri = this.targetUri;
        //redirect
        if (theUrl.startsWith(targetUri)) {
            if(StringUtils.isEmpty(proxyUri)){
                proxyUri = getServerUri(servletRequest);
            }
            theUrl = theUrl.replace(targetUri,proxyUri);
        }
        return theUrl;
    }


    public String getServerUri(HttpServletRequest request) {
        StringBuffer serverUri = new StringBuffer();
        serverUri.append(request.getScheme());//hsot
        serverUri.append(request.getScheme());
        serverUri.append(HTTP_URL_SPLIT_1);
        serverUri.append(request.getServerName());
        serverUri.append(HTTP_URL_SPLIT_2);
        serverUri.append(request.getServerPort());
        serverUri.append(request.getContextPath());
        return serverUri.toString();
    }
}
