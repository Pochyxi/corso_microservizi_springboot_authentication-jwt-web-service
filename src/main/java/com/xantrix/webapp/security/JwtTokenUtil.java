package com.xantrix.webapp.security;

import java.io.Serializable;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Clock;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.impl.DefaultClock;
import lombok.extern.java.Log;

/**
 * Utility per la gestione dei token JWT (JSON Web Token).
 * Fornisce metodi per generare, validare e manipolare token JWT.
 */
@Component
@Log
public class JwtTokenUtil implements Serializable {

	static final String CLAIM_KEY_USERNAME = "sub";
	static final String CLAIM_KEY_CREATED = "iat";

	private static final long serialVersionUID = -3301605591108950415L;
	private final Clock clock = DefaultClock.INSTANCE;

	private final JwtConfig jwtConfig;

	/**
	 * Costruttore che inizializza la configurazione JWT.
	 * @param jwtConfig Configurazione JWT iniettata da Spring
	 */
	@Autowired
	public JwtTokenUtil(JwtConfig jwtConfig)
	{
		this.jwtConfig = jwtConfig;
	}

	/**
	 * Estrae lo username dal token JWT.
	 * @param token Token JWT
	 * @return Username estratto dal token
	 */
	public String getUsernameFromToken(String token)
	{
		return getClaimFromToken(token, Claims::getSubject);
	}

	/**
	 * Ottiene la data di emissione del token.
	 * @param token Token JWT
	 * @return Data di emissione del token
	 */
	public Date getIssuedAtDateFromToken(String token)
	{
		return getClaimFromToken(token, Claims::getIssuedAt);
	}

	/**
	 * Ottiene la data di scadenza del token.
	 * @param token Token JWT
	 * @return Data di scadenza del token
	 */
	public Date getExpirationDateFromToken(String token)
	{
		return getClaimFromToken(token, Claims::getExpiration);
	}

	/**
	 * Estrae un claim specifico dal token JWT.
	 * @param token Token JWT
	 * @param claimsResolver Funzione per estrarre il claim desiderato
	 * @return Valore del claim estratto
	 */
	public <T> T getClaimFromToken(String token, Function<Claims, T> claimsResolver)
	{
		final Claims claims = getAllClaimsFromToken(token);

		if (claims != null)
		{
			log.info(String.format("Emissione Token:  %s", claims.getIssuedAt().toString()));
			log.info(String.format("Scadenza Token:  %s", claims.getExpiration().toString()));

			return claimsResolver.apply(claims);
		}
		else
			return null;
	}

	/**
	 * Estrae tutti i claims dal token JWT.
	 * @param token Token JWT
	 * @return Oggetto Claims contenente tutti i claims del token
	 */
	private Claims getAllClaimsFromToken(String token)
	{
		Claims retVal = null;

		try
		{
			retVal = Jwts.parser()
					.setSigningKey(jwtConfig.getSecret().getBytes())
					.parseClaimsJws(token)
					.getBody();
		}
		catch (Exception ex)
		{
			log.warning(ex.getMessage());
		}

		return retVal;
	}

	/**
	 * Verifica se il token è scaduto.
	 * @param token Token JWT
	 * @return true se il token è ancora valido, false altrimenti
	 */
	private Boolean isTokenExpired(String token)
	{
		final Date expiration = getExpirationDateFromToken(token);

		boolean retVal = expiration != null;

		if (retVal)
		{
			log.info("Token Ancora Valido!");
		}
		else
		{
			log.warning("Token Scaduto o non Valido!");
		}

		return retVal;
	}

	/**
	 * Genera un nuovo token JWT per l'utente specificato.
	 * @param userDetails Dettagli dell'utente
	 * @return Token JWT generato
	 */
	public String generateToken(UserDetails userDetails)
	{
		Map<String, Object> claims = new HashMap<>();
		return doGenerateToken(claims, userDetails);
	}

	/**
	 * Crea effettivamente il token JWT.
	 * @param claims Claims da includere nel token
	 * @param userDetails Dettagli dell'utente
	 * @return Token JWT generato
	 */
	private String doGenerateToken(Map<String, Object> claims, UserDetails userDetails)
	{
		final Date createdDate = clock.now();
		final Date expirationDate = calculateExpirationDate(createdDate);

		final String secret = jwtConfig.getSecret();

		return Jwts.builder()
				.setClaims(claims)
				.setSubject(userDetails.getUsername())
				.claim("authorities", userDetails.getAuthorities()
						.stream()
						.map(GrantedAuthority::getAuthority).collect(Collectors.toList()))
				.setIssuedAt(createdDate)
				.setExpiration(expirationDate)
				.signWith(SignatureAlgorithm.HS512, secret.getBytes())
				.compact();
	}

	/**
	 * Verifica se il token può essere rinnovato.
	 * @param token Token JWT
	 * @return true se il token può essere rinnovato, false altrimenti
	 */
	public Boolean canTokenBeRefreshed(String token)
	{
		return (isTokenExpired(token));
	}

	/**
	 * Rinnova un token JWT esistente.
	 * @param token Token JWT da rinnovare
	 * @return Nuovo token JWT rinnovato
	 */
	public String refreshToken(String token)
	{
		final Date createdDate = clock.now();
		final Date expirationDate = calculateExpirationDate(createdDate);

		final String secret = jwtConfig.getSecret();

		final Claims claims = getAllClaimsFromToken(token);
		claims.setIssuedAt(createdDate);
		claims.setExpiration(expirationDate);

		return Jwts.builder()
				.setClaims(claims)
				.signWith(SignatureAlgorithm.HS512, secret.getBytes())
				.compact();
	}

	/**
	 * Valida un token JWT per un determinato utente.
	 * @param token Token JWT da validare
	 * @param userDetails Dettagli dell'utente
	 * @return true se il token è valido per l'utente specificato, false altrimenti
	 */
	public Boolean validateToken(String token, UserDetails userDetails)
	{
		final String username = getUsernameFromToken(token);

		return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
	}

	/**
	 * Calcola la data di scadenza del token.
	 * @param createdDate Data di creazione del token
	 * @return Data di scadenza del token
	 */
	private Date calculateExpirationDate(Date createdDate)
	{
		return new Date(createdDate.getTime() + jwtConfig.getExpiration() * 1000L );
	}
}
