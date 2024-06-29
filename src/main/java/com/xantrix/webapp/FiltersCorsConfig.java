package com.xantrix.webapp;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

/**
 * Configurazione per gestire le policy CORS (Cross-Origin Resource Sharing).
 * Questa classe permette di definire le regole per le richieste cross-origin.
 */
@Configuration
public class FiltersCorsConfig implements WebMvcConfigurer
{
	/**
	 * Crea e configura un bean WebMvcConfigurer per gestire le impostazioni CORS.
	 * @return Un'istanza di WebMvcConfigurer con le configurazioni CORS personalizzate
	 */
	@Bean
	public WebMvcConfigurer corsConfigurer()
	{
		return new WebMvcConfigurer()
		{
			@Override
			public void addCorsMappings(CorsRegistry registry)
			{
				registry
						.addMapping("/**")                // Applica queste regole CORS a tutti i percorsi
						.allowedOrigins("*")              // Permette richieste da qualsiasi origine
						.allowedMethods("PUT","DELETE","GET","POST","OPTIONS","HEAD","PATCH")  // Metodi HTTP consentiti
						.allowedHeaders("*")              // Permette tutti gli header nelle richieste
						.exposedHeaders("header1","header2","Authorization")  // Header esposti nelle risposte
						.allowCredentials(false)          // Non permette l'invio di credenziali (es. cookies)
						.maxAge(3600);                    // Durata della cache delle pre-flight request (in secondi)
			}
		};
	}
}
