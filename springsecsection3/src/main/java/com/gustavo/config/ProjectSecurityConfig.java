package com.gustavo.config;

import javax.sql.DataSource;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class ProjectSecurityConfig {
	
	@Bean
	SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
		http.authorizeHttpRequests((requests) -> requests
				.requestMatchers("/myAccount","/myBalance","/myLoans","/myCards").authenticated()
				.requestMatchers("/notices","/contact").permitAll())
				.formLogin(Customizer.withDefaults()) // Permite que os usuários se autentiquem com login baseado em formulário
				.httpBasic(Customizer.withDefaults()); // Permite que os usuários se autentiquem com autenticação básica HTTP		
		return http.build();
	}
	
	/*
	@Bean
	public InMemoryUserDetailsManager userDetailsService() {*/
		/*Abordagem 1 onde usamos o método withDefaultPasswordEncoder() 
		  ao criar o user details*/
		/*UserDetails admin = User.withDefaultPasswordEncoder()
			.username("admin")
			.password("12345")
			.authorities("admin")
			.build();
		UserDetails user = User.withDefaultPasswordEncoder()
			.username("user")
			.password("12345")
			.authorities("read")
			.build();
		return new InMemoryUserDetailsManager(admin, user);*/
		
		/*Abordagem 2 onde usamos o NoOpPasswordEncoder Bean 
		  ao criar o user details*/
	/*
		UserDetails admin = User.withUsername("admin")
				.password("12345")
				.authorities("admin")
				.build();
			UserDetails user = User.withUsername("user")
				.password("12345")
				.authorities("read")
				.build();
			return new InMemoryUserDetailsManager(admin, user);
	}
	*/
	
	// Sempre que é adicionada dependências relacionadas ao MySQL e definidas as propriedades 
	// de banco de dados no application.properties, o SPring Bot criará automaticamente um
	// objeto DataSource que contem todos esses detalhes. 
	// JdbcUserDetailsManager usa o banco de dados para armazenar e recuperar as informações do usuário (CRUD).	
	@Bean
	public UserDetailsService userDetailsService(DataSource dataSource) {
		return new JdbcUserDetailsManager(dataSource);
	}
	
	@Bean
	public PasswordEncoder passwordEncoder() {
		return NoOpPasswordEncoder.getInstance();
	}

}
