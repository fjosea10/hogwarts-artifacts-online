package edu.tcu.cs.hogwartsartifactsonline.security;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@Configuration
public class SecurityConfiguration {

    @Value("${api.endpoint.base-url}")
    private String baseUrl;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        return http
                // It is recommended to secure your application at the API endpoint level.
                .authorizeHttpRequests(authorizeHttpRequests -> authorizeHttpRequests
//                        .requestMatchers(HttpMethod.GET, this.baseUrl + "/artifacts/**").permitAll()
                        .requestMatchers(AntPathRequestMatcher.antMatcher(HttpMethod.GET, this.baseUrl + "/artifacts/**")).permitAll()
//                        .requestMatchers(HttpMethod.GET, this.baseUrl + "/users/**").hasAuthority("ROLE_admin") // Protect the endpoint.
//                        .requestMatchers(HttpMethod.POST, this.baseUrl + "/users").hasAuthority("ROLE_admin") // Protect the endpoint.
//                        .requestMatchers(HttpMethod.PUT, this.baseUrl + "/users/**").hasAuthority("ROLE_admin") // Protect the endpoint.
//                        .requestMatchers(HttpMethod.DELETE, this.baseUrl + "/users/**").hasAuthority("ROLE_admin") // Protect the endpoint.
                        .requestMatchers(AntPathRequestMatcher.antMatcher("/h2-console/**")).permitAll() // Explicitly fallback to antMatcher inside requestMatchers.
                        // Disallow everything else.
                        .anyRequest().authenticated() // Always a good idea to put this as last.
                )
                .headers(headers -> headers.frameOptions(HeadersConfigurer.FrameOptionsConfig::disable))
                .csrf(csrf -> csrf.disable())

                /* Configures the spring boot application as an OAuth2 Resource Server which authenticates all
                 the incoming requests (except the ones excluded above) using JWT authentication.
                 */
                .build();
    }
}
