package io.security.basicsecurity.seucrity.config;


import io.security.basicsecurity.seucrity.filter.AjaxLoginProcessingFilter;
import io.security.basicsecurity.seucrity.handler.CustomAccessDeniedHandler;
import io.security.basicsecurity.seucrity.service.CustomUserDetailsService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.WebAuthenticationDetails;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.security.cert.Extension;


@EnableWebSecurity
@RequiredArgsConstructor
@Slf4j
@Order(1)
public class SecurityConfig {

    private final AuthenticationDetailsSource<HttpServletRequest, WebAuthenticationDetails> authenticationDetailsSource;

    private final AuthenticationSuccessHandler customAuthenticationSuccessHandler;

    private final AuthenticationFailureHandler customAuthenticationFailureHandler;

    // WebSecurityConfigurerAdapter ??? ???????????? ?????? SecurityFilterChain ?????? ???????????? ?????????
    // ????????? ?????? ????????? ??? ??????
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        return http
                .authorizeRequests()
                .antMatchers("/","/users","user/login/**","/login*").permitAll()
                .antMatchers("/mypage").hasRole("USER")
                .antMatchers("/messages").hasRole("MANAGER")
                .antMatchers("/config").hasRole("ADMIN")
                .anyRequest()
                .authenticated()
                .and()
                .formLogin()
                .loginPage("/login")
                .loginProcessingUrl("/login_proc")
                .defaultSuccessUrl("/")
                .permitAll()
                .authenticationDetailsSource(authenticationDetailsSource)
                .successHandler(customAuthenticationSuccessHandler)
                .failureHandler(customAuthenticationFailureHandler)
                .and()
                .exceptionHandling()
                .accessDeniedHandler(customAccessDeniedHandler())
                .and()
                .build();
    }
    
    //password ?????????
    @Bean
    public PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    // image, js, css ?????? ?????? ????????? ??????????????? ???????????? ????????? ??????
    // permitAll()??? security filter??? ????????? ????????? ???????????? ????????? ?????????
    // ????????? WebSecurityCustomizer??? filter??? ????????? ????????? ???????????? ?????????.
    @Bean
    public WebSecurityCustomizer webSecurityCustomizer() {
        return web -> {
            web.ignoring().requestMatchers(PathRequest.toStaticResources().atCommonLocations());
            web.ignoring().antMatchers("/favicon.ico", "/resources/**", "/error");
        };
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authConfiguration) throws Exception {
        return authConfiguration.getAuthenticationManager();
    }

    @Bean
    public AccessDeniedHandler customAccessDeniedHandler() {
        CustomAccessDeniedHandler customAccessDeniedHandler = new CustomAccessDeniedHandler();
        customAccessDeniedHandler.setErrorPage("/denied");
        return customAccessDeniedHandler;
    }

}













//2.7?????? ?????? ????????? ?????????
//    @Bean
//    public UserDetailsManager users() {
//        String password = passwordEncoder().encode("1111");
//
//        UserDetails user = User.builder()
//                .username("user")
//                .password(password)
//                .roles("USER")
//                .build();
//
//        UserDetails sys = User.builder()
//                .username("manager")
//                .password(password)
//                .roles("MANAGER")
//                .build();
//
//        UserDetails admin = User.builder()
//                .username("admin")
//                .password(password)
//                .roles("ADMIN","USER","MANAGER")
//                .build();
//
//        return new InMemoryUserDetailsManager( user, sys, admin );
//    }







// AuthenticationManager ??? ?????? ??? ??????????????? AuthenticationProvider ????????? ???????????? ??? ??????
//    @Bean
//    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
//        ProviderManager authenticationManager = (ProviderManager) authenticationConfiguration.getAuthenticationManager();
//        authenticationManager.getProviders().add(customAuthenticationProvider());
//        return authenticationManager;
//    }
//    @Bean
//    public CustomAuthenticationProvider customAuthenticationProvider() {
//        return new CustomAuthenticationProvider();
//    }

//    @Bean
//    public PasswordEncoder passwordEncoder() {
//        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
//    }

//http
//                .authorizeRequests()
//                .antMatchers("/user").hasRole("USER")
//                .antMatchers("/admin/pay").hasRole("ADMIN")
//                .antMatchers("/admin/**").access("hasRole('ADMIN') or hasRole('SYS')")
//                .anyRequest().authenticated()
//                .and()
//                .formLogin()
//                //????????? ????????? ??????
//                //.loginPage("/loginPage")
//                //????????? ?????? ??? ???????????? url
//                .defaultSuccessUrl("/")
//                //?????? ??? ???????????? url
//                .failureUrl("/login")
//                .usernameParameter("userId")
//                .passwordParameter("passwd")
//                //??????????????? ???????????????
//                .loginProcessingUrl("/login_proc")
//                //?????? ??? ???????????? ?????????
//                .successHandler((req,resp,auth) -> {
//                            System.out.println(auth.getName());
//                            resp.sendRedirect("/");
//                        })
//                //?????? ??? ???????????? ?????????
//                .failureHandler((req, resp, exception) -> {
//                    System.out.println("exception" + exception.getMessage());
//                    resp.sendRedirect("/login");
//
//                })
//                .permitAll()
//                .and()
//                .logout()
//                .logoutUrl("/logout")
//                .logoutSuccessUrl("/login")
//                .addLogoutHandler(((request, response, authentication) -> {
//                    HttpSession session = request.getSession();
//                    session.invalidate();
//                }))
//                .logoutSuccessHandler((request, response, authentication) -> response.sendRedirect("/login"))
//                .deleteCookies("remember-me")
//                .and()
//                .rememberMe()
//                // ?????? ?????????????????? remember-me
//                .rememberMeParameter("remember")
//                // default 14???
//                .tokenValiditySeconds(3600)
//                //????????? ??? ????????? ??????????????? ????????? ?????? ?????? -> ?????? false
//                .alwaysRemember(true)
//                // ???????????? ?????? ????????? ????????? ???????????? ???????????? ?????????
//                .and()
//                .sessionManagement()
//                .maximumSessions(1)
//                // default false -> ????????? ?????? ????????? ??? ?????? ?????? ????????? ???????????? (???????????? ????????????) ???????????? ???????????? ?????????
//                .maxSessionsPreventsLogin(true)
//                .and()
//                // ?????? ?????? ????????? ???????????? ????????? ?????? ??? ???????????? ????????? ?????????????????? ????????????.
//                .sessionFixation()
//                .changeSessionId()
//                .and()
//                .build();

//        return http
//
//                .authorizeRequests()
//                .antMatchers("/mypage").hasRole("USER")
//                .antMatchers("/messages").hasRole("MANAGER")
//                .antMatchers("/config").hasRole("ADMIN")
//                .antMatchers("/**").permitAll()
//                .and()
//                .formLogin()
//                .loginPage("/login")
//                .loginProcessingUrl("/login_proc")
//                .permitAll()
//                .and()
//                .build();
//    }






