package org.formVlidation.config;

import org.formVlidation.service.UserDetailServiceImpli;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;


@Configuration
@EnableWebSecurity
public class WebSecurityConfig  extends WebSecurityConfigurerAdapter{
	 @Autowired
	    UserDetailServiceImpli userDetailsService;
	 
	    @Bean
	    public BCryptPasswordEncoder passwordEncoder() {
	        BCryptPasswordEncoder bCryptPasswordEncoder = new BCryptPasswordEncoder();
	        return bCryptPasswordEncoder;
	    }
	     
	     
	    @Autowired
	    public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception { 
	 
	    	// Configuration du service pour trouver l'utilisateur dans la base de données.
	    	// Et définition du mot de passeEncoder
	        auth.userDetailsService(userDetailsService).passwordEncoder(passwordEncoder());     
	 
	    }
	 
	    @Override
	    protected void configure(HttpSecurity http) throws Exception {
	 
	        http.csrf().disable();
	 
	     // Les pages ne nécessitent pas de connexion
	        http.authorizeRequests().antMatchers("/", "/login", "/logout").permitAll();
	 
	     // La page userInfo nécessite une connexion en tant que ROLE_USER ou ROLE_ADMIN.
	     // S'il n'y a pas de connexion, il sera redirigé vers la page / login.
	        http.authorizeRequests().antMatchers("/userInfo").access("hasAnyRole('ROLE_USER', 'ROLE_ADMIN')");
	 
	        // la page pour ladmin seulement 
	        http.authorizeRequests().antMatchers("/admin").access("hasRole('ROLE_ADMIN')");
	 
	 
	     // Lorsque l'utilisateur s'est connecté en tant que utilisateur .
	     // Mais accédez à une page qui nécessite le rôle admin ,
	     // AccessDeniedException sera levée.
	        http.authorizeRequests().and().exceptionHandling().accessDeniedPage("/403");
	 
	        // Config pour le formulaire de login 
	        http.authorizeRequests().and().formLogin()//
	                // Submit URL of login page.
	                .loginProcessingUrl("/j_spring_security_check") // Submit URL
	                .loginPage("/login")//
	                .defaultSuccessUrl("/userAccountInfo")//
	                .failureUrl("/login?error=true")//
	                .usernameParameter("username")//
	                .passwordParameter("password")
	                // Config pour la  page logout 
	                .and().logout().logoutUrl("/logout").logoutSuccessUrl("/logoutSuccessful");
	 
	    }

}
