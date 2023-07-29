package com.gustavo.config;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfTokenRequestAttributeHandler;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;

import java.util.Collections;

@Configuration
public class ProjectSecurityConfig {
	
	@Bean
	SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
		http.cors().configurationSource(new CorsConfigurationSource() {
				@Override
				public CorsConfiguration getCorsConfiguration(HttpServletRequest request) {
					CorsConfiguration config = new CorsConfiguration();
					// Configura uma lista de origens para as quais as cross-origin requests são permitidas
					config.setAllowedOrigins(Collections.singletonList("http://localhost:4200"));
					// Configura os quais métodos HTTP serão aceitos
					config.setAllowedMethods(Collections.singletonList("*"));
					// Define se as credenciais do usuário são suportadas
					config.setAllowCredentials(true);
					// Defina a lista de cabeçalhos que serão aceitos
					config.setAllowedHeaders(Collections.singletonList("*"));
					// Define por quando tempo o navegador pode se lembrar(em cache) dessas configuraçãoes (em segundos)
					config.setMaxAge(3600L);
					return config;
				}
			})	
			.and()
			.csrf(csrf -> csrf.disable())
			.authorizeHttpRequests((requests) -> requests				
			.requestMatchers("/myAccount","/myBalance","/myLoans","/myCards", "/user").authenticated()
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
