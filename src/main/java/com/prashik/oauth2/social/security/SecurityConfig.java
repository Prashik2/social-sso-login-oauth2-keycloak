package com.prashik.oauth2.social.security;

import java.util.ArrayList;
import java.util.List;

import org.keycloak.adapters.springboot.KeycloakAutoConfiguration;
import org.keycloak.adapters.springsecurity.authentication.KeycloakAuthenticationProvider;
import org.keycloak.adapters.springsecurity.config.KeycloakWebSecurityConfigurerAdapter;
import org.keycloak.adapters.springsecurity.filter.KeycloakAuthenticatedActionsFilter;
import org.keycloak.adapters.springsecurity.filter.KeycloakAuthenticationProcessingFilter;
import org.keycloak.adapters.springsecurity.filter.KeycloakPreAuthActionsFilter;
import org.keycloak.adapters.springsecurity.filter.KeycloakSecurityContextRequestFilter;
import org.keycloak.adapters.springsecurity.management.HttpSessionManager;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.authentication.configuration.GlobalAuthenticationConfigurerAdapter;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.client.endpoint.DefaultJwtBearerTokenResponseClient;
import org.springframework.security.oauth2.server.resource.introspection.NimbusOpaqueTokenIntrospector;
import org.springframework.security.oauth2.server.resource.introspection.NimbusReactiveOpaqueTokenIntrospector;
import org.springframework.security.oauth2.server.resource.introspection.OpaqueTokenIntrospector;
import org.springframework.security.oauth2.server.resource.web.BearerTokenResolver;
import org.springframework.security.oauth2.server.resource.web.DefaultBearerTokenResolver;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
import org.springframework.security.web.method.annotation.CsrfTokenArgumentResolver;
import org.springframework.security.web.util.matcher.RequestHeaderRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

import jakarta.security.auth.message.config.AuthConfig;

@Configuration
@EnableWebSecurity
public class SecurityConfig {
	
	@Autowired
	AuthenticationSuccessHandler successHandler;
	
//	@Bean
//	public AuthenticationManager authenticatioManager(AuthenticationManagerBuilder authConfig) throws Exception{
//		//authConfig.authenticationProvider(new KeycloakAuthenticationProvider());
//		return authConfig.build();
//	}
	
//	@Bean
//	public AuthenticationProvider authenticatioProvider(AuthenticationConfiguration authConfig) throws Exception{
//		return authConfig.ger.getAuthenticationManager();
//	}
	
//	@Bean
//    public FilterRegistrationBean keycloakAuthenticationProcessingFilterRegistrationBean(
//            KeycloakAuthenticationProcessingFilter filter) {
//        FilterRegistrationBean registrationBean = new FilterRegistrationBean(filter);
//        registrationBean.setEnabled(false);
//        return registrationBean;
//    }
//
//    @Bean
//    public FilterRegistrationBean keycloakPreAuthActionsFilterRegistrationBean(
//            KeycloakPreAuthActionsFilter filter) {
//        FilterRegistrationBean registrationBean = new FilterRegistrationBean(filter);
//        registrationBean.setEnabled(false);
//        return registrationBean;
//    }
//
//    @Bean
//    public FilterRegistrationBean keycloakAuthenticatedActionsFilterBean(
//            KeycloakAuthenticatedActionsFilter filter) {
//        FilterRegistrationBean registrationBean = new FilterRegistrationBean(filter);
//        registrationBean.setEnabled(false);
//        return registrationBean;
//    }
//
//    @Bean
//    public FilterRegistrationBean keycloakSecurityContextRequestFilterBean(
//        KeycloakSecurityContextRequestFilter filter) {
//        FilterRegistrationBean registrationBean = new FilterRegistrationBean(filter);
//        registrationBean.setEnabled(false);
//        return registrationBean;
//    }
//
//    @Bean
//   // @Override
//    @ConditionalOnMissingBean(HttpSessionManager.class)
//    protected HttpSessionManager httpSessionManager() {
//        return new HttpSessionManager();
//    }
	
	@Bean
	BearerTokenResolver getBearerTokenResolver() {
		DefaultBearerTokenResolver bearerTokenResolver = new DefaultBearerTokenResolver();
	    bearerTokenResolver.setBearerTokenHeaderName(HttpHeaders.AUTHORIZATION);
	    return bearerTokenResolver;
		}	
	@Bean
	public OpaqueTokenIntrospector introspector() {
	    return new NimbusOpaqueTokenIntrospector("http://localhost:8080/realms/cognologix/protocol/openid-connect/token/introspect", "dummyclient", "i0B9LazRTIM6klkkLcuvhIdKCSzwC8DL");
	}
	
//	@Bean
//	public NimbusReactiveOpaqueTokenIntrospector introspectorManager() {
//	    return new NimbusReactiveOpaqueTokenIntrospector("http://localhost:8080/realms/cognologix/protocol/openid-connect/token/introspect", "dummyclient", "i0B9LazRTIM6klkkLcuvhIdKCSzwC8DL");
//	}
	
	@Bean
	public RequestMatcher acceptHeaderRequestMatcher() {
	    return new RequestHeaderRequestMatcher("Accept", "*/*");
	}	
	
  @Bean
  LoginUrlAuthenticationEntryPoint loginUrl() { 
   return new LoginUrlAuthenticationEntryPoint("http://localhost:8080/realms/cognologix/protocol/openid-connect/auth");
  }

  
  
  @Bean
  public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
    http
        .csrf()
        .disable()
        .authorizeHttpRequests()
        .requestMatchers("/login","/login/**","/oauth2/**","/api/v1/demo/welcome").permitAll()
        .requestMatchers("/api/v1/demo/user").hasRole("user")
        .anyRequest()
        .authenticated()
        .and()
        .oauth2Login().authorizationEndpoint(Customizer.withDefaults());//.authorizationRedirectStrategy(new DefaultRedirectStrategy());
    http.authenticationProvider(new KeycloakAuthenticationProvider());
   // http.authenticationManager(authenticatioManager(new AuthenticationConfiguration()));
    //.successHandler(successHandler).failureHandler(failureHandler());
//        .and()
//        .formLogin().loginPage("/login").successHandler(successHandler)
//        .and().csrf().disable()
//        .logout().logoutUrl("/logout").logoutSuccessUrl("/login")
//        .and().oauth2Login().loginPage("/login").successHandler(successHandler);
//    ;
    http.oauth2ResourceServer().opaqueToken();
    http.cors().disable();
    return http.build();
  }
  
  @Bean
  SimpleUrlAuthenticationFailureHandler failureHandler() {
	  System.out.println("Authentication failed");
      return new SimpleUrlAuthenticationFailureHandler("http://localhost:8081/api/v1/demo/welcome");
  }
}
