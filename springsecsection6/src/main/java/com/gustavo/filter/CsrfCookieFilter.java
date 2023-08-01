package com.gustavo.filter;

import java.io.IOException;

import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.filter.OncePerRequestFilter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

// OncePerRequestFilter - filtro que é executado apenas uma vez por solicitação.
public class CsrfCookieFilter extends OncePerRequestFilter {

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		// Tenta ler o CsrfToken disponível dentro do HttpServletRequest
		CsrfToken csrfToken = (CsrfToken) request.getAttribute(CsrfToken.class.getName());
		// Verifica se há um valor do cabeçalho dentro deste objeto
		// Se não for nulo, isso significa que a estrutura pode ter gerado o csrfToken.
		if(null != csrfToken.getHeaderName()) {
			// Preenche o mesmo HeaderName e é um valor de token dentro do cabeçalho de resposta e a mesma 
			// resposta será entregue ao próximo filtro dentro da cadeia de filtros. Dessa forma, 
			// eventualmente, sempre que for enviado a resposta para a aplicação UI, o valor 
			// csrfToken estará presente dentro do cabeçalho.
			// Está apenas apenas sendo enviando o cabeçalho, mas não o cookie. 
			// Quando o valor CsrfToken  é preenchido como parte do cabeçalho de resposta, a 
			// estrutura Spring Security se encarregará de gerar o cookie CSRF e enviá-lo ao navegador 
			// ou aplicativo de interface do usuário como parte da resposta.
			response.setHeader(csrfToken.getHeaderName(), csrfToken.getToken());
		}
		filterChain.doFilter(request, response);
	}

}
