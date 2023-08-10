package com.gustavo.filter;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import com.gustavo.constants.SecurityConstants;

import javax.crypto.SecretKey;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Collection;
import java.util.Date;
import java.util.HashSet;
import java.util.Set;

public class JWTTokenGeneratorFilter extends OncePerRequestFilter {

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		// Obtem os detalhes do usuário autenticado
		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		if(null != authentication) {
			// Cria uma nova instância de SecretKey para uso com algoritmos HMAC-SHA com base na matriz de bytes de uma chave secreta especificada.
			SecretKey key = Keys.hmacShaKeyFor(SecurityConstants.JWT_KEY.getBytes(StandardCharsets.UTF_8));
			// Cria o token JWT
			String jwt = Jwts.builder().setIssuer("Eazy Bank").setSubject("JWT Token")
					.claim("username", authentication.getName())
					.claim("authorities", populateAuthorities(authentication.getAuthorities()))
					.setIssuedAt(new Date())
					.setExpiration(new Date((new Date()).getTime() + 30000000))
	                .signWith(key).compact();
			response.setHeader(SecurityConstants.JWT_HEADER, jwt);
		}
		
		filterChain.doFilter(request, response);
	}
	
	@Override
	// Define que o filtro deve ser executado apenas durante o processo de login
	protected boolean shouldNotFilter(HttpServletRequest request) {
		return !request.getServletPath().equals("/user");
	}
	
	// Vai ler todas Authorities e formar uma String com elas
	public String populateAuthorities(Collection<? extends GrantedAuthority> collection) {
		Set<String> authoritiesSet = new HashSet<>();
		for(GrantedAuthority authority : collection) {
			authoritiesSet.add(authority.getAuthority());
		}
		return String.join(",", authoritiesSet);
	}

}
