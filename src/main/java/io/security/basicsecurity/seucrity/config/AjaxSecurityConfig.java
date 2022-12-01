package io.security.basicsecurity.seucrity.config;


import io.security.basicsecurity.seucrity.common.AjaxLoginAuthenticationEntryPoint;
import io.security.basicsecurity.seucrity.filter.AjaxLoginProcessingFilter;
import io.security.basicsecurity.seucrity.handler.AjaxAccessDeniedHandler;
import io.security.basicsecurity.seucrity.handler.AjaxAuthenticationFailureHandler;
import io.security.basicsecurity.seucrity.handler.AjaxAuthenticationSuccessHandler;
import io.security.basicsecurity.seucrity.provider.AjaxAuthenticationProvider;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@EnableWebSecurity
@Order(0)
@RequiredArgsConstructor
public class AjaxSecurityConfig{

    private final PasswordEncoder passwordEncoder;
    private final UserDetailsService userDetailsService;

    private final AuthenticationConfiguration authenticationConfiguration;

    @Bean
    public AuthenticationProvider ajaxAuthenticationProvider() {
        return new AjaxAuthenticationProvider(userDetailsService, passwordEncoder);
    }

    @Bean
    public AuthenticationManager ajaxAuthenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception{
        ProviderManager authenticationManager = (ProviderManager) authenticationConfiguration.getAuthenticationManager();
        authenticationManager.getProviders().add(ajaxAuthenticationProvider());
        return authenticationManager;
    }
    @Bean
    SecurityFilterChain ajaxAuthenticationSecurityFilterChain(HttpSecurity http) throws Exception {
        http
                .antMatcher("/api/**")
                .authorizeRequests()
                .antMatchers("/api/messages").hasRole("MANAGER")
                .antMatchers("/api/login").permitAll()
                .anyRequest().authenticated();

//        http.addFilterBefore(ajaxLoginProcessingFilter(), UsernamePasswordAuthenticationFilter.class);

        http
                .exceptionHandling()
                .authenticationEntryPoint(new AjaxLoginAuthenticationEntryPoint())
                .accessDeniedHandler(ajaxAccessDeniedHandler());

        customConfigurerAjax(http);
        return http.build();
    }

    private void customConfigurerAjax(HttpSecurity http) throws Exception {
        http
                .apply(new AjaxLoginConfigurer<>())
                .successHandlerAjax(ajaxAuthenticationSuccessHandler())
                .failureHandlerAjax(ajaxAuthenticationFailureHandler())
                .setAuthenticationManager(ajaxAuthenticationManager(authenticationConfiguration))
                .loginProcessingUrl("/api/login");
    }

    @Bean
    public AccessDeniedHandler ajaxAccessDeniedHandler() {
        return new AjaxAccessDeniedHandler();
    }

//    @Bean
//    public AjaxLoginProcessingFilter ajaxLoginProcessingFilter() throws Exception{
//        AjaxLoginProcessingFilter ajaxLoginProcessingFilter = new AjaxLoginProcessingFilter();
//        ajaxLoginProcessingFilter.setAuthenticationManager(ajaxAuthenticationManager(authenticationConfiguration));
//        ajaxLoginProcessingFilter.setAuthenticationSuccessHandler(ajaxAuthenticationSuccessHandler());
//        ajaxLoginProcessingFilter.setAuthenticationFailureHandler(ajaxAuthenticationFailureHandler());
//        return ajaxLoginProcessingFilter;
//    }

    @Bean
    public AuthenticationSuccessHandler ajaxAuthenticationSuccessHandler() {
        return new AjaxAuthenticationSuccessHandler();
    }

    @Bean
    public AuthenticationFailureHandler ajaxAuthenticationFailureHandler() {
        return new AjaxAuthenticationFailureHandler();
    }
}
