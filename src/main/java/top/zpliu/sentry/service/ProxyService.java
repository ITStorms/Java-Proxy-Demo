package top.zpliu.sentry.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import top.zpliu.sentry.proxy.ProxyClient;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Service
public class ProxyService {

    @Autowired
    private ProxyClient proxyClient;
    public void go(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse) throws ServletException, IOException {
        proxyClient.go(httpServletRequest,httpServletResponse);
    }
}
