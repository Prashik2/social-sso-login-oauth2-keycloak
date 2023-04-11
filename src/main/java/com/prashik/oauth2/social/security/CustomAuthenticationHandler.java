package com.prashik.oauth2.social.security;

import java.io.IOException;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Component
public class CustomAuthenticationHandler implements AuthenticationSuccessHandler{

//	@Autowired
//	UserRepository userRepo;
//	
//	@Autowired
//	DefaultUserService userService;
//		
	@Override
	public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
			Authentication authentication) throws IOException, ServletException {

		String redirectUrl = null;
		if(authentication.getPrincipal() instanceof DefaultOAuth2User) {
		DefaultOAuth2User  userDetails = (DefaultOAuth2User ) authentication.getPrincipal();
         String username = userDetails.getAttribute("email") !=null?userDetails.getAttribute("email"):userDetails.getAttribute("login")+"@gmail.com" ;
//          if(userRepo.findByEmail(username) == null) {
//        	  UserRegisteredDTO user = new UserRegisteredDTO();
//        	  user.setEmail_id(username);
//        	  user.setName(userDetails.getAttribute("email") !=null?userDetails.getAttribute("email"):userDetails.getAttribute("login"));
//        	  user.setPassword(("Dummy"));
//        	  user.setRole("USER");
//        	  userService.save(user);
//          }
		}  
		redirectUrl = "/api/v1/demo/user";
		new DefaultRedirectStrategy().sendRedirect(request, response, redirectUrl);
	}

}
