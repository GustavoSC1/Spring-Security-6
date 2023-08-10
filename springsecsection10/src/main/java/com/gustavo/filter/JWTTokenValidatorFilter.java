package com.gustavo.filter;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

import javax.crypto.SecretKey;

import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import com.gustavo.constants.SecurityConstants;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

public class JWTTokenValidatorFilter extends OncePerRequestFilter {

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		// Obtem o valor do cabeçalho Authorization
		String jwt = request.getHeader(SecurityConstants.JWT_HEADER);
		if(null != jwt) {
			try {
				// Gera a SecretKey novamente
				SecretKey key = Keys.hmacShaKeyFor(
						SecurityConstants.JWT_KEY.getBytes(StandardCharsets.UTF_8));
				
				// Valida o token JWT
				// Para validar token JWT é necessário passar a chave de assinatura para verificar a assinatura JWT.
				Claims claims = Jwts.parserBuilder()
						.setSigningKey(key)
						.build()
						.parseClaimsJws(jwt)
						.getBody();
				
				String username = String.valueOf(claims.get("username"));
				String authorities = (String) claims.get("authorities");
				// Cria o objeto Authentication com o username e as authorities obtidos do token
				Authentication auth = new UsernamePasswordAuthenticationToken(username, null,
						AuthorityUtils.commaSeparatedStringToAuthorityList(authorities));
				SecurityContextHolder.getContext().setAuthentication(auth);
			} catch(Exception e) {
				throw new BadCredentialsException("Invalid Token received!");
			}
		}
		filterChain.doFilter(request, response);
	}
	
	@Override
	// O filtro só não deve ser executado na operação de login
	protected boolean shouldNotFilter(HttpServletRequest request) {
		return request.getServletPath().equals("/user");
	}

}
