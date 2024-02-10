package com.code.empcrud.jwtservice.services;

import com.code.empcrud.jwtservice.controllers.AuthRequest;
import com.code.empcrud.jwtservice.controllers.AuthenticationResponse;
import com.code.empcrud.jwtservice.controllers.RegisterRequest;
import com.code.empcrud.jwtservice.enums.Role;
import com.code.empcrud.jwtservice.model.User;
import com.code.empcrud.jwtservice.repositories.UserRepository;
import com.code.empcrud.jwtservice.security.JwtAuthenticationProvider;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthService {
    private final UserRepository userRepository;
    private final JwtAuthenticationProvider jwtAuthenticationProvider;
    private static PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }
    private final AuthenticationManager authenticationManager;

    public AuthenticationResponse register(RegisterRequest registerRequest){
        User user = User.builder()
                .firstName(registerRequest.getFirstName())
                .lastName(registerRequest.getLastName())
                .email(registerRequest.getEmail())
                .password(passwordEncoder().encode(registerRequest.getPassword()))
                .role(Role.USER)
                .build();
        userRepository.save(user);
        String jwtToken = jwtAuthenticationProvider.generateToken(user);
        return AuthenticationResponse.builder().token(jwtToken).build();
    }

    public AuthenticationResponse authenticate(AuthRequest request){
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(request.getEmail(), request.getPassword())
        );
        var user = userRepository.findUserByEmail(request.getEmail()).orElseThrow(() -> new UsernameNotFoundException("The user not found"));
        String jwtToken = jwtAuthenticationProvider.generateToken(user);
        return AuthenticationResponse.builder().token(jwtToken).build();
    }

}
