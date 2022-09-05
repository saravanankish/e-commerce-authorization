package com.saravanank.authorizationserver.service;

import java.util.Arrays;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.apache.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import com.saravanank.authorizationserver.model.User;
import com.saravanank.authorizationserver.repository.UserRepository;

@Service
public class UserService implements UserDetailsService {

	private static final Logger logger = Logger.getLogger(UserService.class);

	@Autowired
	private UserRepository userRepo;

	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		User user = userRepo.findByUsername(username);
		if (user == null) {
			logger.warn("User with username " + username + " not found");
			throw new UsernameNotFoundException("No user found");
		}
		logger.info("User with username " + username + " was sent");
		return new org.springframework.security.core.userdetails.User(user.getUsername(), user.getPassword(),
				user.isAccountActive(), true, true, user.isEmailVerified(), getAuthorities(Arrays.asList(user.getRole())));
	}

	private Collection<? extends GrantedAuthority> getAuthorities(List<String> roles) {
		// TODO Auto-generated method stub
		Set<GrantedAuthority> authorities = new HashSet<>();
		for (String role : roles) {
			authorities.add(new SimpleGrantedAuthority("ROLE_" + role));
		}
		return authorities;
	}

	public User findByUsername(String username) {
		logger.info("User with username " + username + " was requested");
		return userRepo.findByUsername(username);
	}
}
