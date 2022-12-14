package com.saravanank.authorizationserver.config;

import org.apache.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;

import com.saravanank.authorizationserver.model.User;
import com.saravanank.authorizationserver.service.UserService;

public class CustomAccessTokenClaim implements OAuth2TokenCustomizer<JwtEncodingContext> {

	private static final Logger logger = Logger.getLogger(CustomAccessTokenClaim.class);
	
	@Autowired
	private UserService userService;

	@Override
	public void customize(JwtEncodingContext context) {
		User user = userService.findByUsername(context.getPrincipal().getName());
		if(user != null && user.getRole() != null) {			
			logger.info("Returned token for user with role " + user.getRole());
			context.getClaims().claims(existingClaims -> {
				existingClaims.put("role", user.getRole());
			});
		}
	}
}
