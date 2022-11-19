package io.security.basicsecurity;


import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    // image, js, css 등의 정적 파일을 시큐리티가 필터하지 않도록 설정
//    @Bean
//    public WebSecurityCustomizer webSecurityCustomizer() {
//        return web -> web.ignoring().requestMatchers(PathRequest.toStaticResources().atCommonLocations());
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

    // WebSecurityConfigurerAdapter 를 상속하지 않고 SecurityFilterChain 빈을 생성해서 사용함
    // 여러개 빈을 설정할 수 있음
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        return http
                .authorizeRequests()
                .anyRequest().authenticated()
                .and()
                .formLogin()
                .and()
                .build();

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
    }
}
