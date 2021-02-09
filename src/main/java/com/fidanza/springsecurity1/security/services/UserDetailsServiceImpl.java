package com.fidanza.springsecurity1.security.services;

import com.fidanza.springsecurity1.model.User;
import com.fidanza.springsecurity1.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * – UserDetailsServiceImpl implements UserDetailsService that will override loadUserByUsername method.
 * loadUserByUsername method will find a record from users database tables to build a UserDetails object
 * for authentication.
 */

@Service
public class UserDetailsServiceImpl implements UserDetailsService {

    @Autowired
    UserRepository userRepository;

    @Override
    @Transactional
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userRepository.findByUsername(username).orElseThrow(() ->
            new UsernameNotFoundException("User Not Found with -> username or email :" + username)
        );

        return UserPrinciple.build(user);
    }
}
