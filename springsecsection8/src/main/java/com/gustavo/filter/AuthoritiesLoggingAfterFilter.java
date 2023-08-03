package com.gustavo.filter;

import java.io.IOException;
import java.util.logging.Logger;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;

public class AuthoritiesLoggingAfterFilter implements Filter {
	
	private final Logger LOG = 
			Logger.getLogger(AuthoritiesLoggingAfterFilter.class.getName());

	@Override
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
			throws IOException, ServletException {
		
		// Obtem os detalhes do usuário authenticado
		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		if(null != authentication) {
			LOG.info("User" + authentication.getName() + " is successfully authenticated and "
					+ "has the authorities " + authentication.getAuthorities().toString());
		}
		
		chain.doFilter(request, response);
		
	}

}
