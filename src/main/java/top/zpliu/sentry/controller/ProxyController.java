package top.zpliu.sentry.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import top.zpliu.sentry.service.ProxyService;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@RestController
public class ProxyController {

    @Autowired
    private ProxyService service;
    @RequestMapping("/**")
    public void proxy(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse) throws ServletException, IOException {
        service.go(httpServletRequest,httpServletResponse);
    }
}
