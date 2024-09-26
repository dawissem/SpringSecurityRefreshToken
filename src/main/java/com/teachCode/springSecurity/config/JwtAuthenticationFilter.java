package com.teachCode.springSecurity.config;

import com.teachCode.springSecurity.service.JwtService;
import com.teachCode.springSecurity.service.UserService;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

//@Component: Cette annotation indique à Spring que cette classe est un composant géré
// par le conteneur Spring et qu'elle doit être instantiée lors de la configuration de l'application.
@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {
    // Cette classe étend OncePerRequestFilter, qui est une classe abstraite fournie
// par Spring qui garantit qu'une seule exécution du filtre se produit pour chaque demande.
// Cela signifie que le filtre ne sera exécuté qu'une fois même si la requête traverse plusieurs filtres.
    private final JwtService jwtService;
    private final UserService userService;
    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request,
                                    @NonNull HttpServletResponse response, @NonNull FilterChain filterChain)
            throws ServletException, IOException {
        //Bearer : Une chaîne constante qui définit le préfixe du jeton JWT dans l'en-tête HTTP. Il est défini sur "Bearer".
        //Autorization : Une chaîne constante qui définit le nom de l'en-tête HTTP où le jeton JWT sera placé.
        // Il est défini sur "Authorization".
        final String authHeader = request.getHeader("Authorization");
        final String jwt;
        final String userEmail;
        if (org.apache.commons.lang3.StringUtils.isEmpty(authHeader) || !StringUtils.startsWithIgnoreCase(authHeader, "Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }
        jwt = authHeader.substring(7);
        userEmail = jwtService.extractUserName(jwt);
        if (org.apache.commons.lang3.StringUtils.isNotEmpty(userEmail)
                &&  SecurityContextHolder.getContext().getAuthentication() == null) {
    UserDetails userDetails = userService.userDetailsService()
            .loadUserByUsername(userEmail);
    if (jwtService.isTokenValid(jwt, userDetails)) {
        SecurityContext context = SecurityContextHolder.createEmptyContext();
        UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                userDetails, null, userDetails.getAuthorities());
        //WebAuthenticationDetailsSource().buildDetails(request)); configure les détails de l'authentification.
        // Ici, un nouvel objet WebAuthenticationDetails est créé à partir de la requête HTTP actuelle (request).
        // Les détails de la demande HTTP,
        // tels que l'adresse IP du client et le navigateur utilisé, sont inclus dans cet objet d'authentification.
        authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
        context.setAuthentication(authToken);
        SecurityContextHolder.setContext(context);
    }
}
        filterChain.doFilter(request, response);
    }
}
