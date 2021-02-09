package com.fidanza.springsecurity1.controller;

import com.fidanza.springsecurity1.model.Role;
import com.fidanza.springsecurity1.model.RoleName;
import com.fidanza.springsecurity1.model.User;
import com.fidanza.springsecurity1.repository.RoleRepository;
import com.fidanza.springsecurity1.repository.UserRepository;
import com.fidanza.springsecurity1.request.LoginForm;
import com.fidanza.springsecurity1.request.SignUpForm;
import com.fidanza.springsecurity1.response.JwtResponse;
import com.fidanza.springsecurity1.security.jwt.JwtProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import javax.validation.Valid;
import java.util.HashSet;
import java.util.Set;

/**
 * – AuthRestAPIs.java defines 2 APIs:
 *
 * /api/auth/signup: sign up
 * -> check username/email is already in use.
 * -> create User object
 * -> store to database
 * /api/auth/signin: sign in
 * -> attempt to authenticate with AuthenticationManager bean.
 * -> add authentication object to SecurityContextHolder
 * -> Generate JWT token, then return JWT to client
 */

@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/api/auth")
public class AuthRestAPI {
    
    @Autowired
    AuthenticationManager authenticationManager;
    
    @Autowired
    UserRepository userRepository;
    
    @Autowired
    RoleRepository roleRepository;
    
    @Autowired
    PasswordEncoder encoder;
    
    @Autowired
    JwtProvider jwtProvider;

    @PostMapping("/signin")
    public ResponseEntity<?> authenticateUser(@Valid @RequestBody LoginForm loginRequest) {
        Authentication authentication = authenticationManager.authenticate(
            new UsernamePasswordAuthenticationToken(
                    loginRequest.getUsername(),
                    loginRequest.getPassword()
            )
        );

        SecurityContextHolder.getContext().setAuthentication(authentication);

        String jwt = jwtProvider.generateJwtToken(authentication);
        return new ResponseEntity<>(new JwtResponse(jwt), HttpStatus.OK);
    }

    @PostMapping("/signup")
    public ResponseEntity<?> registerUser(@Valid @RequestBody SignUpForm signUpRequest) {

        if (userRepository.existsByUsername(signUpRequest.getUsername())) {
            return new ResponseEntity<String>("Fail -> Username is already taken!", HttpStatus.BAD_REQUEST);
        }

        if (userRepository.existsByEmail(signUpRequest.getEmail())) {
            return new ResponseEntity<String>("Fail -> Email is already in use!", HttpStatus.BAD_REQUEST);
        }

        // Creating user's account
        User user = new User(signUpRequest.getName(), signUpRequest.getUsername(),
                signUpRequest.getEmail(), encoder.encode(signUpRequest.getPassword()));

        Set<String> strRoles = signUpRequest.getRole();
        Set<Role> roles = new HashSet<>();

        strRoles.forEach(role -> {
            switch (role) {
                case "admin":
                    Role adminRole = roleRepository.findByName(RoleName.ROLE_ADMIN)
                            .orElseThrow(() -> new RuntimeException("Fail! -> Case: User role not found."));
                    roles.add(adminRole);

                    break;
                case "pm":
                    Role pmRole = roleRepository.findByName(RoleName.ROLE_PM)
                            .orElseThrow(() -> new RuntimeException("Fail! -> Case: User role not found."));
                    roles.add(pmRole);

                    break;
                default:
                    Role userRole = roleRepository.findByName(RoleName.ROLE_USER)
                            .orElseThrow(() -> new RuntimeException("Fail! -> Case: User Role not found."));
            }
        });

        LoginForm loginForm = new LoginForm(signUpRequest.getUsername(), signUpRequest.getPassword());
        user.setRoles(roles);
        userRepository.save(user);

        return authenticateUser(loginForm);
//        return ResponseEntity.ok().body("User registered successfully!");

    }


}
