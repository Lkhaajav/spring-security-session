package com.example.session.controller;

import java.util.Collection;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

import com.example.session.dto.CustomUserDetails;

@RestController
public class MainController {

	@PostMapping("/")
	public Object main() {
		
		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		
		Map<String, Object> map = new HashMap<>();
		
		if(authentication == null) {
			map.put("isLoggedIn", false);
			return map;
		}
		
		/*
		 * if(authentication instanceof AnonymousAuthenticationToken) {
		 * map.put("isLoggedIn", false); return map; }
		 */
		
		CustomUserDetails customUserDetails = (CustomUserDetails) authentication.getPrincipal();

        String username = customUserDetails.getUsername();

        Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();
        Iterator<? extends GrantedAuthority> iterator = authorities.iterator();
        GrantedAuthority auth = iterator.next();
        String role = auth.getAuthority();
		
		if (role.equals("ROLE_ANONYMOUS")) {
			map.put("isLoggedIn", false);
			return map;
        }
		
		map.put("isLoggedIn", true);
		map.put("username", username);
		map.put("role", role);		
		
		return map;
	}
}
