//package com.in28minutes.rest.webservices.restfulwebservices.basic;
//
//
//import org.springframework.boot.autoconfigure.graphql.GraphQlProperties;
//import org.springframework.context.annotation.Bean;
//import org.springframework.context.annotation.Configuration;
//import org.springframework.http.HttpMethod;
//import org.springframework.security.config.Customizer;
//import org.springframework.security.config.annotation.web.builders.HttpSecurity;
//import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
//import org.springframework.security.config.http.SessionCreationPolicy;
//import org.springframework.security.web.SecurityFilterChain;
//

//public class BasicSecurityConfig {
//    @Bean
//    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
//
//        //This adds authentication to all the paths
//        http.authorizeHttpRequests(auth->auth.requestMatchers(HttpMethod.OPTIONS, "/**").permitAll().anyRequest().authenticated());
//        //This gives the basic login popup without it no explicit login interface is given until .login page is not used
//                http.httpBasic(Customizer.withDefaults());
//                http.sessionManagement(session->session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
//                http.csrf(AbstractHttpConfigurer::disable);
//
//        return http.build();
//    }
//}
