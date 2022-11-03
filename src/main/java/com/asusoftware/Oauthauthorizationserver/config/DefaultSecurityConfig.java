package com.asusoftware.Oauthauthorizationserver.config;

import org.springframework.context.annotation.Bean;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;

@EnableWebSecurity
public class DefaultSecurityConfig {

    @Bean
    SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        // All the request here should be authenticated
        http.authorizeRequests(authorizeRequests ->
                authorizeRequests.anyRequest().authenticated())
                .formLogin(Customizer.withDefaults()); // with default form login for the authorization server
        return http.build();
    }
}
