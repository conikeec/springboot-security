package org.conikee.rest.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.security.SecurityProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;

@Configuration
@EnableGlobalMethodSecurity(prePostEnabled = true)
@Order(SecurityProperties.ACCESS_OVERRIDE_ORDER)
class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private UserDetailsService userDetailsService;

    @Override
    protected void configure(HttpSecurity http) throws Exception {

        //Content Security Policy (CSP) is an added layer of security that helps mitigate XSS (cross-site scripting) and data injection attacks. 
        //To enable it, you need to configure your app to return a Content-Security-Policy header. 
        //You can also use a <meta http-equiv="Content-Security-Policy"> tag in your HTML page.
        http.headers()   
           .contentSecurityPolicy("script-src 'self' https://trustedscripts.example.com; object-src https://trustedplugins.example.com; report-uri /csp-report-endpoint/");
        

        // clickjacking protection to your site. 
        // If you do not use frames, the safest measure is to provide X-Frame-Options DENY HTTP header. 
        // If you use frames, but just from your origin, you should use X-Frame-Options SAMEORIGIN. 
        // If you need to allow frames from a trusted host, the situation is a bit trickier. 
        // Due to browser compatibility issues, you need to provide both X-Frame-Options ALLOW-FROM and  
        // Content Security Policy frame-ancestors directive to make sure you cover as many client browsers 
        // as possible. Of course, legacy browsers do not support either of the HTTP headers and you  
        // will need to deploy Framebuster javascript to reduce the risk. 
        http.headers()
            .frameOptions().sameOrigin().contentSecurityPolicy("frame-ancestors 'self'");

        http.authorizeRequests()
                .antMatchers("/", "/public/**").permitAll()
                .antMatchers("/users/**").hasAuthority("ADMIN")
                .anyRequest()
                    .fullyAuthenticated()
                .and()
                    .requiresChannel()
                    .anyRequest()
                    .requiresSecure()
                .and()
                    .csrf()
                    .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
                .and()
                    .formLogin()
                    .loginPage("/login")
                    .failureUrl("/login?error")
                    .usernameParameter("email")
                    .permitAll()
                .and()
                    .logout()
                    .logoutUrl("/logout")
                    .deleteCookies("remember-me")
                    .logoutSuccessUrl("/")
                    .permitAll()
                .and()
                    .rememberMe();
    }

    @Override
    public void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth
        .userDetailsService(userDetailsService)
        .passwordEncoder(new BCryptPasswordEncoder());
    }

}