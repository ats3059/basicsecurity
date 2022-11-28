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

    // WebSecurityConfigurerAdapter 를 상속하지 않고 SecurityFilterChain 빈을 생성해서 사용함
    // 여러개 빈을 설정할 수 있음
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
    
    //password 암호화
    @Bean
    public PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    // image, js, css 등의 정적 파일을 시큐리티가 필터하지 않도록 설정
    // permitAll()은 security filter를 통해서 권한이 필요한지 확인을 하지만
    // 아래의 WebSecurityCustomizer는 filter를 통해서 권한을 확인하지 않는다.
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













//2.7부터 유저 등록이 변경됨
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







// AuthenticationManager 빈 참조 및 사용자정의 AuthenticationProvider 객체를 설정해야 할 경우
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
//                //로그인 페이지 설정
//                //.loginPage("/loginPage")
//                //로그인 성공 시 이동하는 url
//                .defaultSuccessUrl("/")
//                //실패 시 이동하는 url
//                .failureUrl("/login")
//                .usernameParameter("userId")
//                .passwordParameter("passwd")
//                //로그인처리 엔드포인트
//                .loginProcessingUrl("/login_proc")
//                //성공 시 동작하는 핸들러
//                .successHandler((req,resp,auth) -> {
//                            System.out.println(auth.getName());
//                            resp.sendRedirect("/");
//                        })
//                //실패 시 동작하는 핸들러
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
//                // 기본 파라미터명은 remember-me
//                .rememberMeParameter("remember")
//                // default 14일
//                .tokenValiditySeconds(3600)
//                //리멤버 미 기능이 활성화되지 않아도 항상 실행 -> 기본 false
//                .alwaysRemember(true)
//                // 시스템에 있는 사용자 계정을 조회할때 사용하는 클래스
//                .and()
//                .sessionManagement()
//                .maximumSessions(1)
//                // default false -> 세션이 초과 되었을 때 현재 지금 인증을 시도하는 (로그인을 시도하는) 접속자를 실패하게 만든다
//                .maxSessionsPreventsLogin(true)
//                .and()
//                // 세션 고정 공격을 막기위해 로그인 시도 시 계속해서 새로운 세션아이디를 생성한다.
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






