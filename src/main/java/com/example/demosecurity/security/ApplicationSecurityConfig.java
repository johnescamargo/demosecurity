package com.example.demosecurity.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import static com.example.demosecurity.security.ApplicationUserRole.*;

@SuppressWarnings("deprecation")
@Configuration
@EnableWebSecurity
public class ApplicationSecurityConfig extends WebSecurityConfigurerAdapter {
	
	private final PasswordEncoder passwordEncoder;
	
	
	@Autowired
	public ApplicationSecurityConfig(PasswordEncoder passwordEncoder) {
		this.passwordEncoder = passwordEncoder;
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http
			.authorizeHttpRequests()
			.antMatchers("/", "index", "/css/*" , "/js/*").permitAll()
			.antMatchers("/api/**").hasRole(STUDENT.name())
			.anyRequest()
			.authenticated()
			.and()
			.httpBasic();
	}
	
	//Retrieve users from database
	@Override
	@Bean
	protected UserDetailsService userDetailsService() {
		UserDetails johnesUser = User.builder()
					.username("johnescamargo")
					.password(passwordEncoder.encode("password"))
					.roles(STUDENT.name())// ROLE_STUDENT
					.build();
		
		UserDetails cintiaUser = User.builder()
				.username("cintia")
				.password(passwordEncoder.encode("password"))
				.roles(ADMIN.name())// ROLE_STUDENT
				.build();
		
		return new InMemoryUserDetailsManager(johnesUser, cintiaUser);
	}
}
