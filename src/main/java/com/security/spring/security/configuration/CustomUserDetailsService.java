package com.security.spring.security.configuration;

import com.security.spring.security.model.DBUser;
import com.security.spring.security.repository.DBUserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

@Service
public class CustomUserDetailsService {

    @Autowired
    private DBUserRepository dbUserRepository;

    // on enleve impl UserDetailService qui force a definir un AuthenticationProvider personnalisé
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        DBUser user = dbUserRepository.findByUsername(username);
        return new User(user.getUsername(), user.getPassword(), getGrantedAuthorities(user.getRole()));
    }

    private List<GrantedAuthority> getGrantedAuthorities(String role) {
        List<GrantedAuthority> authorities = new ArrayList<GrantedAuthority>();
        authorities.add(new SimpleGrantedAuthority("ROLE_"+role));
        return authorities;
    }
}
