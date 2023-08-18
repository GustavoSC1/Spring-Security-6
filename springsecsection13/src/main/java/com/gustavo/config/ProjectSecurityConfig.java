package com.gustavo.config;

import com.gustavo.filter.CsrfCookieFilter;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfTokenRequestAttributeHandler;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;

import java.util.Arrays;
import java.util.Collections;

@Configuration
public class ProjectSecurityConfig {
	
	@Bean
	SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
		// Disponibiliza o CsrfToken para a aplicação front-end como um atributo da request.
		// Essa implementação também resolve (aceita e valida) o valor do token da solicitação como um cabeçalho de solicitação
		// ou um parâmetro de solicitação (_csrf por padrão).
		CsrfTokenRequestAttributeHandler requestHandler = new CsrfTokenRequestAttributeHandler();
		// define o nome do atributo em que o CsrfToken será preenchido
		requestHandler.setCsrfRequestAttributeName("_csrf");
		
		JwtAuthenticationConverter jwtAuthenticationConverter = new JwtAuthenticationConverter();
        jwtAuthenticationConverter.setJwtGrantedAuthoritiesConverter(new KeycloakRoleConverter());
		
		http
			.sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS)) // Nenhuma sessão sempre será criada.
			
			.cors().configurationSource(new CorsConfigurationSource() {
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
					// Defina a lista de cabeçalhos expostos
					config.setExposedHeaders(Arrays.asList("Authorization"));
					// Define por quando tempo o navegador pode se lembrar(em cache) dessas configuraçãoes (em segundos)
					config.setMaxAge(3600L);
					return config;
				}
			})	
			.and()
			.csrf(csrf -> csrf.csrfTokenRequestHandler(requestHandler).ignoringRequestMatchers("/contact","/register")
			// É responsável por persistir o token CSRF em um cookie com nome XSRF-TOKEN para o front-end. 
			// Como o "HttpOnly" foi definido como falso, o front-end poderá recuperar esse cookie usando JavaScript.					
				.csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse()))
			// Execute CsrfCookieFilter após BasicAuthenticationFilter
			// BasicAuthenticationFilter é um filtro do Spring Security que é executado quando usamos a Autenticação Básica HTTP
			// Filtro responsável por enviar o cookie e o valor do cabeçalho para o front-end após o login inicial.
			.addFilterAfter(new CsrfCookieFilter(), BasicAuthenticationFilter.class)
			.authorizeHttpRequests((requests) -> requests		
				.requestMatchers("/myAccount").hasRole("USER")
				.requestMatchers("/myBalance").hasAnyRole("USER", "ADMIN")
				.requestMatchers("/myLoans").hasRole("USER")
				.requestMatchers("/myCards").hasRole("USER")
				.requestMatchers("/user").authenticated()
				.requestMatchers("/notices","/contact","/register").permitAll())
			// Informa ao framework Spring Security que a aplicação Spring Boot vai atuar como um 
			// oauth2ResourceServer com o JSON Web Token (JWT).
			.oauth2ResourceServer(oauth2ResourceServerCustomizer ->
            	oauth2ResourceServerCustomizer.jwt(jwtCustomizer -> jwtCustomizer.jwtAuthenticationConverter(jwtAuthenticationConverter)));
		return http.build();
	}	

}
