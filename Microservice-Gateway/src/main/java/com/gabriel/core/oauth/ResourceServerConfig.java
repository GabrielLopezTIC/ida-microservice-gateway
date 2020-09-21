 package com.gabriel.core.oauth;


import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configurers.ResourceServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;

@Configuration
@EnableResourceServer
public class ResourceServerConfig extends ResourceServerConfigurerAdapter{

	@Override
	public void configure(ResourceServerSecurityConfigurer resources) throws Exception {
		resources.tokenStore(tokenStore());
	}

	@Override
	public void configure(HttpSecurity http) throws Exception {
		http.cors() 
		.and()
		.authorizeRequests()
		.antMatchers(HttpMethod.POST,"/api/security/oauth/token").permitAll()
		.antMatchers(HttpMethod.GET,"/api/users/users/find/all").hasAnyRole("ADMIN","USER")
		.antMatchers(HttpMethod.GET,"/api/users/users/find/usr/{email}").hasAnyRole("ADMIN","USER")
		.antMatchers(HttpMethod.DELETE,"/api/users/users/delete/usr/{email}").hasRole("ADMIN")
		.antMatchers(HttpMethod.POST,"/api/users/users/save/usr").hasRole("ADMIN")
		
		.antMatchers(HttpMethod.POST,"/api/ida/file/uploadAndProcessImg").hasAnyRole("USER","ADMIN")		
		.antMatchers(HttpMethod.POST,"/api/ida/file/uploadAndProcessDispersos").hasAnyRole("USER","ADMIN")
		.antMatchers("/api/ida/file/zip").hasAnyRole("USER","ADMIN")
		

		
		
		.anyRequest().authenticated(); 
		
	}

	@Bean
	public JwtTokenStore tokenStore() {
		return new JwtTokenStore(accesTokenConverter());
	}
	
	@Bean
	public JwtAccessTokenConverter accesTokenConverter() {
		JwtAccessTokenConverter token = new JwtAccessTokenConverter();
		token.setSigningKey("claveToken");
		return token;
	}
	

}
