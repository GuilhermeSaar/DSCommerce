package com.devsuperior.dscommerce.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

// classe de configuracao
@Configuration
public class SecurityConfig {


    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    // Este metodo configura a segurança HTTP da aplicação usando o objeto HttpSecurity, que oferece várias opções
    //  para definir como as requisições HTTP serão tratadas
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        // o CSRF (Cross-Site Request Forgery) está sendo desativado
        http.csrf(csrf -> csrf.disable());
        //  todas as requisições HTTP (anyRequest()) estão permitidas sem nenhuma autenticação (permitAll())
        http.authorizeHttpRequests(auth -> auth.anyRequest().permitAll());
        return http.build();
    }

}
