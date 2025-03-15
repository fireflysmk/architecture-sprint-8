package ru.yandex_practicum.reports_api;

import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.env.Environment;

@SpringBootApplication
public class ReportsApiApplication {

	private static final Logger logger = LoggerFactory.getLogger(ReportsApiApplication.class);

	@Autowired
	private Environment environment;

	public static void main(String[] args) {

		SpringApplication.run(ReportsApiApplication.class, args);

		logger.info("we started!");

		if(args.length > 0) {
			logger.info("THERES SOME ARGS...");
			for (String arg : args) {
				logger.info("Argument: {}", arg);
			}
		} else  {
			logger.info("NO ARGS   args.length == 0");
		}

	}
	@PostConstruct
	public void logConfig() {
		logger.info("Application configuration: {}", environment.getProperty("spring.security.oauth2.resourceserver.jwt.issuer-uri"));
	}

}
