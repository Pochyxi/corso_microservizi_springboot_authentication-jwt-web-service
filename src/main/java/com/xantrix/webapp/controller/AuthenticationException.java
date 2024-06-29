package com.xantrix.webapp.controller;

/**
 * Eccezione personalizzata per gestire errori di autenticazione nel sistema.
 * Estende RuntimeException, quindi è un'eccezione non controllata.
 */
public class AuthenticationException extends RuntimeException
{
	// Identificatore di serializzazione per garantire la consistenza durante la deserializzazione
	private static final long serialVersionUID = 5978387939943664344L;

	/**
	 * Costruttore per creare una nuova AuthenticationException.
	 *
	 * @param message Il messaggio di errore che descrive l'eccezione.
	 * @param cause La causa originale (throwable) che ha portato a questa eccezione.
	 */
	public AuthenticationException(String message, Throwable cause)
	{
		super(message, cause);
	}
}
