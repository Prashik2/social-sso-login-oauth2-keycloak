package com.prashik.oauth2.social.demo;

import java.security.Principal;

import org.springframework.boot.autoconfigure.security.oauth2.resource.OAuth2ResourceServerProperties.Opaquetoken;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/demo")
public class DemoController {

  @CrossOrigin(origins = "http://localhost:8081")
  @GetMapping("/welcome")
  public ResponseEntity<String> sayHello(Principal principal,Opaquetoken token,JwtAuthenticationToken jwtToken) {
	  SecurityContext securityContext = SecurityContextHolder.getContext();
      securityContext.getAuthentication().isAuthenticated();
      String princ = principal!=null?principal.getName():"No principal";
      String tokenop =token!=null?token.toString():"No token";
      String jwtToken1 =jwtToken!=null?jwtToken.toString():"No token";
    return ResponseEntity.ok("Welcome Pahe"+securityContext.toString() + princ + tokenop + jwtToken1);
  }
  
  @CrossOrigin(origins = "http://localhost:8081")
  @GetMapping("/user")
  public ResponseEntity<String> user() {
    return ResponseEntity.ok("Hello Oauth2");
  }
  
}
