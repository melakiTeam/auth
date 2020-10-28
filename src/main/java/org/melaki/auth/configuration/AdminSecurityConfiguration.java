package org.melaki.auth.configuration;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.DelegatingPasswordEncoder;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.www.DigestAuthenticationEntryPoint;
import org.springframework.security.web.authentication.www.DigestAuthenticationFilter;

import javax.sql.DataSource;

@Configuration
@Order(1)
public class AdminSecurityConfiguration extends WebSecurityConfigurerAdapter {

    @Autowired
    private DataSource dataSource;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.exceptionHandling().authenticationEntryPoint(digestAuthenticationEntryPoint())
                .and()
                .headers().disable()
                .antMatcher("/admin/**")
                .addFilter(digestAuthenticationFilter())
                .exceptionHandling().authenticationEntryPoint(digestAuthenticationEntryPoint())
                .and().authorizeRequests().antMatchers("/admin/**").hasAuthority("ADMIN");

    }

    private DigestAuthenticationEntryPoint digestAuthenticationEntryPoint() {
        DigestAuthenticationEntryPoint digestAuthenticationEntryPoint = new DigestAuthenticationEntryPoint();
        digestAuthenticationEntryPoint.setRealmName("sebaRealm");
        digestAuthenticationEntryPoint.setKey("sebaKEy"); //key that will be used to generate nonce
        return digestAuthenticationEntryPoint;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
//        PasswordEncoder delegatingPasswordEncoder = PasswordEncoderFactories.createDelegatingPasswordEncoder();
//        delegatingPasswordEncoder.encode("noop");
//        return delegatingPasswordEncoder;
//        return NoOpPasswordEncoder.getInstance();
        return NoOpPasswordEncoder.getInstance();
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.jdbcAuthentication().dataSource(dataSource).passwordEncoder(passwordEncoder());
//        auth.inMemoryAuthentication().withUser("seba").password("seba").roles("ADMIN");
    }

    @Bean
    public UserDetailsService userDetailsService() {
        return super.userDetailsService();
    }

    private DigestAuthenticationFilter digestAuthenticationFilter() {
        DigestAuthenticationFilter digestAuthenticationFilter = new DigestAuthenticationFilter();
        digestAuthenticationFilter.setUserDetailsService(userDetailsService());
        digestAuthenticationFilter.setAuthenticationEntryPoint(digestAuthenticationEntryPoint());
        return digestAuthenticationFilter;
    }



}
