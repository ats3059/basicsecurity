package io.security.basicsecurity.controller;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
@Slf4j
public class HomeController {

    @GetMapping(value="/")
    public String home() throws Exception {
        SecurityContext context = SecurityContextHolder.getContext();
        log.info("name = {}",context.getAuthentication().getName());
        return "home";
    }

}
