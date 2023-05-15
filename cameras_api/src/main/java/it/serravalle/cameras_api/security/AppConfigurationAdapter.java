package it.serravalle.cameras_api.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;


@Configuration
@EnableWebSecurity
public class AppConfigurationAdapter {

	@Autowired
	private MyBasicAuthenticationEntryPoint authenticationEntryPoint;
    
	@Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.csrf().disable()
        	.headers().frameOptions().disable()
        	.and()
        	.authorizeHttpRequests()
        	.requestMatchers("/private/**").hasRole("ADMIN")
    		.requestMatchers("/**").hasRole("USER")
    		.and()
            .httpBasic().authenticationEntryPoint(authenticationEntryPoint);
        return http.build();
    }
    @Bean
    public PasswordEncoder encoder() {
        return new BCryptPasswordEncoder();
    }
    
}
