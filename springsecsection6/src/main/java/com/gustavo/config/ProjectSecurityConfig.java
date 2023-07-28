package com.gustavo.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class ProjectSecurityConfig {
	
	@Bean
	SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
		http.csrf(csrf -> csrf.disable())
			.authorizeHttpRequests((requests) -> requests				
			.requestMatchers("/myAccount","/myBalance","/myLoans","/myCards").authenticated()
			.requestMatchers("/notices","/contact","/register").permitAll())
			.formLogin(Customizer.withDefaults()) // Permite que os usuários se autentiquem com login baseado em formulário
			.httpBasic(Customizer.withDefaults()); // Permite que os usuários se autentiquem com autenticação básica HTTP		
		return http.build();
	}	
	
	@Bean
	public PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}

}
