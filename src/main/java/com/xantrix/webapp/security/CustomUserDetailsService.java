package com.xantrix.webapp.security;

import java.net.URI;
import java.net.URISyntaxException;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.client.support.BasicAuthenticationInterceptor;
import org.springframework.security.core.userdetails.User.UserBuilder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import lombok.SneakyThrows;
import lombok.extern.java.Log;

/**
 * Servizio personalizzato per il caricamento dei dettagli utente.
 * Implementa UserDetailsService di Spring Security per l'autenticazione.
 */
@Service("customUserDetailsService")
@Log
public class CustomUserDetailsService implements UserDetailsService
{
	// Configurazione utente
	private final UserConfig Config;

	/**
	 * Costruttore che inizializza la configurazione utente.
	 * @param Config Configurazione utente iniettata da Spring
	 */
	@Autowired
	public CustomUserDetailsService(UserConfig Config)
	{
		this.Config = Config;
	}

	/**
	 * Carica i dettagli dell'utente dato lo username.
	 * @param UserId ID dell'utente da caricare
	 * @return UserDetails oggetto contenente i dettagli dell'utente
	 * @throws UsernameNotFoundException se l'utente non viene trovato
	 */
	@Override
	@SneakyThrows
	public UserDetails loadUserByUsername(String UserId)
	{
		String ErrMsg = "";

		// Verifica la validità dell'ID utente
		if (UserId == null || UserId.length() < 2)
		{
			ErrMsg = "Nome utente assente o non valido";
			log.warning(ErrMsg);
			throw new UsernameNotFoundException(ErrMsg);
		}

		// Recupera i dettagli dell'utente tramite chiamata HTTP
		Utenti utente = this.GetHttpValue(UserId);

		// Verifica se l'utente è stato trovato
		if (utente == null)
		{
			ErrMsg = String.format("Utente %s non Trovato!!", UserId);
			log.warning(ErrMsg);
			throw new UsernameNotFoundException(ErrMsg);
		}

		// Costruisce l'oggetto UserDetails
		UserBuilder builder = null;
		builder = org.springframework.security.core.userdetails.User.withUsername(utente.getUserId());
		builder.disabled((!utente.getAttivo().equals( "Si" )));
		builder.password(utente.getPassword());

		// Converte i ruoli dell'utente in autorità Spring Security
		String[] profili = utente.getRuoli()
				.stream().map(a -> "ROLE_" + a).toArray(String[]::new);

		builder.authorities(profili);

		return builder.build();
	}

	/**
	 * Recupera i dettagli dell'utente tramite una chiamata HTTP.
	 * @param UserId ID dell'utente da recuperare
	 * @return Utenti oggetto contenente i dettagli dell'utente, null se non trovato
	 */
	private Utenti GetHttpValue(String UserId)
	{
		URI url = null;

		try
		{
			String SrvUrl = Config.getSrvUrl();
			url = new URI(SrvUrl + UserId);
		}
		catch (URISyntaxException e)
		{
			e.printStackTrace();
		}

		// Configura il client REST con autenticazione di base
		RestTemplate restTemplate = new RestTemplate();
		restTemplate.getInterceptors().add(new BasicAuthenticationInterceptor(Config.getUserId(), Config.getPassword()));

		Utenti utente = null;

		try
		{
			// Esegue la richiesta HTTP GET
			utente = restTemplate.getForObject(url, Utenti.class);
		}
		catch (Exception e)
		{
			String ErrMsg = "Connessione al servizio di autenticazione non riuscita!!";
			log.warning(ErrMsg);
		}

		return utente;
	}
}
	