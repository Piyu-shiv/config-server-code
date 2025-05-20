package com.prodev.spring.cloud.config.config_server.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class SecurityConfig {

    private Environment env;

    @Autowired
    public SecurityConfig(Environment environment) {
        this.env = environment;
    }

    @Bean
    SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(auth -> auth.requestMatchers(HttpMethod.POST, "/actuator/busrefresh").hasRole("ADMIN")
                        .requestMatchers(HttpMethod.GET, "/**").hasRole("CLIENT").
                        anyRequest().authenticated()).csrf(csrf -> csrf.ignoringRequestMatchers("/actuator/busrefresh"))
                .httpBasic(Customizer.withDefaults());
        return http.build();
    }

    @Bean
    InMemoryUserDetailsManager userDetailsService() {
        UserDetails admin = User.withUsername("admin").password(passwordEncoder().encode(env.getProperty("spring.security.user.password"))).roles("ADMIN").build();
        UserDetails client = User.withUsername("client").password(passwordEncoder().encode(env.getProperty("my-security.user.password"))).roles("CLIENT").build();

        return new InMemoryUserDetailsManager(admin,client);
    }

    @Bean
    PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
