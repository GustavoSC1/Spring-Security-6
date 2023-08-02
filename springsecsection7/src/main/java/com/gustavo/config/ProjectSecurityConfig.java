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

import com.gustavo.filter.CsrfCookieFilter;

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
		
		http
			 // O objetivo desta configuração é informar ao Spring Security para que ele sempre crie o 
		     // JSESSIONID após a conclusão do login inicial. E o mesmo JSESSIONID será enviado para o 
		     // aplicativo de interface do usuário e meu aplicativo de interface do usuário pode aproveitar 
		     // o mesmo para todas as solicitações subsequentes que ele fará após o login inicial. 	
		     // JSESSIONID não contém nenhum dado do usuário, como nome de usuário, funções ou autoridades. 
		     // É apenas um valor gerado aleatoriamente. 
		     // https://www.linkedin.com/pulse/jsessionid-spring-security-shanawaj-mansuri/
			.securityContext((securityContext) -> securityContext.requireExplicitSave(false))			
			.sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.ALWAYS)) // Uma sessão sempre será criada se ainda não existir.
			
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
				.requestMatchers("/myAccount").hasAuthority("VIEWACCOUNT")
				.requestMatchers("/myBalance").hasAnyAuthority("VIEWACCOUNT", "VIEWBALANCE")
				.requestMatchers("/myLoans").hasAuthority("VIEWLOANS")
				.requestMatchers("/myCards").hasAuthority("VIEWCARDS")
				.requestMatchers("/user").authenticated()
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
