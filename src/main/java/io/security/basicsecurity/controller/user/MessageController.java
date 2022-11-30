package io.security.basicsecurity.controller.user;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
public class MessageController {

    @GetMapping("/message")
    public String messages() {
        return "user/messages";
    }


    @ResponseBody
    @GetMapping("/api/messages")
    public String apiMessage() {
        return "messages ok";
    }
}
