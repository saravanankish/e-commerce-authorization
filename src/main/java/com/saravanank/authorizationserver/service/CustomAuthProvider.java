package com.saravanank.authorizationserver.service;


import org.apache.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AccountExpiredException;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class CustomAuthProvider implements AuthenticationProvider {
	
	private static final Logger logger = Logger.getLogger(CustomAuthProvider.class);

	@Autowired
	private UserService userService;
	
	@Autowired
	private PasswordEncoder passwordEncoder;
	
	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		String username = authentication.getName();
		String password = authentication.getCredentials().toString();
		UserDetails user = userService.loadUserByUsername(username);
		if(!user.isEnabled()) {
			logger.info("User account of user tired to login was deleted");			
			throw new AccountExpiredException("User account deleted");
		}
		logger.info("User authentication request received");
		return checkPass(user, password);
	}

	private Authentication checkPass(UserDetails user, String password) {
		if(passwordEncoder.matches(password, user.getPassword())) {
			logger.info("User authenicated successfully");
			return new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword(), user.getAuthorities());
		} else {
			logger.info("Invalid password was used to login");
			throw new BadCredentialsException("Incorrect password");
		}
	}

	@Override
	public boolean supports(Class<?> authentication) {
		return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
	}

}
