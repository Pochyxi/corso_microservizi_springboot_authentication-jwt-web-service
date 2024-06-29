package com.xantrix.webapp.controller;

import java.util.Objects;

import javax.servlet.http.HttpServletRequest;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import com.xantrix.webapp.security.JwtTokenUtil;

import lombok.SneakyThrows;
import lombok.extern.java.Log;

@RestController
@Log
public class JwtAuthenticationRestController
{
	@Value("${sicurezza.header}")
	private String tokenHeader;

	private final AuthenticationManager authenticationManager;
	private final JwtTokenUtil jwtTokenUtil;
	private final UserDetailsService userDetailsService;

	/**
	 * Costruttore per JwtAuthenticationRestController.
	 *
	 * @param authenticationManager Gestore dell'autenticazione
	 * @param jwtTokenUtil Utility per la gestione dei token JWT
	 * @param userDetailsService Servizio per caricare i dettagli dell'utente
	 */
	@Autowired
	public JwtAuthenticationRestController(AuthenticationManager authenticationManager,
										   JwtTokenUtil jwtTokenUtil,
										   @Qualifier("customUserDetailsService") UserDetailsService userDetailsService)
	{
		this.authenticationManager = authenticationManager;
		this.jwtTokenUtil = jwtTokenUtil;
		this.userDetailsService = userDetailsService;
	}

	/**
	 * Endpoint per la creazione di un token di autenticazione.
	 *
	 * @param authenticationRequest Richiesta contenente username e password
	 * @return ResponseEntity con il token JWT
	 */
	@PostMapping(value = "${sicurezza.uri}")
	@SneakyThrows
	public ResponseEntity<JwtTokenResponse> createAuthenticationToken(@RequestBody JwtTokenRequest authenticationRequest)
	{
		log.info("Autenticazione e Generazione Token");

		authenticate(authenticationRequest.getUsername(), authenticationRequest.getPassword());

		final UserDetails userDetails = userDetailsService
				.loadUserByUsername(authenticationRequest.getUsername());

		final String token = jwtTokenUtil.generateToken(userDetails);

		log.warning(String.format("Token %s", token));

		return ResponseEntity.ok(new JwtTokenResponse(token));
	}

	/**
	 * Endpoint per il refresh del token di autenticazione.
	 *
	 * @param request HttpServletRequest contenente il token attuale
	 * @return ResponseEntity con il nuovo token JWT
	 */
	@GetMapping(value = "${sicurezza.refresh}")
	@SneakyThrows
	public ResponseEntity<JwtTokenResponse> refreshAndGetAuthenticationToken(HttpServletRequest request)
	{
		log.info("Tentativo Refresh Token");
		String authToken = request.getHeader(tokenHeader);

		if (authToken == null)
		{
			throw new Exception("Token assente o non valido!");
		}

        if (jwtTokenUtil.canTokenBeRefreshed( authToken ))
		{
			String refreshedToken = jwtTokenUtil.refreshToken( authToken );

			log.warning(String.format("Refreshed Token %s", refreshedToken));

			return ResponseEntity.ok(new JwtTokenResponse(refreshedToken));
		}
		else
		{
			return ResponseEntity.badRequest().body(null);
		}
	}

	/**
	 * Gestore delle eccezioni di autenticazione.
	 *
	 * @param e Eccezione di autenticazione
	 * @return ResponseEntity con messaggio di errore
	 */
	@ExceptionHandler({ AuthenticationException.class })
	public ResponseEntity<String> handleAuthenticationException(AuthenticationException e)
	{
		return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(e.getMessage());
	}

	/**
	 * Metodo privato per l'autenticazione dell'utente.
	 *
	 * @param username Nome utente
	 * @param password Password
	 * @throws AuthenticationException se l'autenticazione fallisce
	 */
	private void authenticate(String username, String password)
	{
		Objects.requireNonNull(username);
		Objects.requireNonNull(password);

		try
		{
			authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(username, password));
		}
		catch (DisabledException e)
		{
			log.warning("UTENTE DISABILITATO");
			throw new AuthenticationException("UTENTE DISABILITATO", e);
		}
		catch (BadCredentialsException e)
		{
			log.warning("CREDENZIALI NON VALIDE");
			throw new AuthenticationException("CREDENZIALI NON VALIDE", e);
		}
	}
}
