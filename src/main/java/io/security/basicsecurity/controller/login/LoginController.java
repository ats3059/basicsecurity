package io.security.basicsecurity.controller.login;

import io.security.basicsecurity.domain.Account;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Optional;

@Controller
public class LoginController {

    @GetMapping("/login")
    public String login(
            @RequestParam(value = "error" , required = false) String error
            , @RequestParam(value = "exception" , required = false) String exception
            , Model model
    )
    {
        model.addAttribute("error", error);
        model.addAttribute("exception", exception);
        return"user/login/login";
    }

    @GetMapping("/logout")
    public String logout(HttpServletRequest req, HttpServletResponse resp) {
        Optional<Authentication> authOpt = Optional.ofNullable(SecurityContextHolder.getContext().getAuthentication());

        authOpt.ifPresent(auth -> new SecurityContextLogoutHandler().logout(req,resp,auth));

        return "redirect:/login";
    }

    @GetMapping("/denied")
    public String accessDenied(
            @RequestParam(value = "exception" , required = false) String exception
            ,Model model) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        Account account = (Account)authentication.getPrincipal();
        model.addAttribute("username", account.getUserName());
        model.addAttribute("exception", exception);

        return "user/login/denied";
    }

}
