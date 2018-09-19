package top.zpliu.sentry.controller;

import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/admin")
public class AdminController {

    @RequestMapping("")
    public String main(){
        return "hello admin";
    }

    @RequestMapping("/say")
    public String say(){
        return "hello say";
    }
}
