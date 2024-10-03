package com.example.session.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.example.session.login.LoginFilter;

@Configuration
@EnableWebSecurity
public class SecurityConfig {
	
	private final AuthenticationConfiguration authenticationConfiguration;
	
	public SecurityConfig(AuthenticationConfiguration authenticationConfiguration) {

        this.authenticationConfiguration = authenticationConfiguration;
    }
	
	@Bean
    AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {

        return configuration.getAuthenticationManager();
    }
	
	@Bean
    BCryptPasswordEncoder bCryptPasswordEncoder() {

        return new BCryptPasswordEncoder();
    }
	
	@Bean
	SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
		
		http
			.csrf((auth) -> auth.disable());
		
		http
			.formLogin((auth) -> auth.disable());
		
		http
			.httpBasic((auth) -> auth.disable());
		
		http
        	.authorizeHttpRequests((auth) -> auth
                .requestMatchers("/", "/login").permitAll()
                .anyRequest().authenticated());
		
		
		http
			.addFilterAt(new LoginFilter(authenticationManager(authenticationConfiguration)), UsernamePasswordAuthenticationFilter.class);

		http
	    	.sessionManagement((session) -> session
	            .maximumSessions(1)
	            .maxSessionsPreventsLogin(true)
            );
	
		http
	        .sessionManagement((session) -> session
	            .sessionFixation((sessionFixation) -> sessionFixation
	                .newSession()
	            )
	        );
		
		http
	    	.sessionManagement((session) -> session
	    		.sessionFixation().changeSessionId()
    		);
		
		return http.build();
		
	}

}
