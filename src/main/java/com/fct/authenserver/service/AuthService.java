package com.fct.authenserver.service;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.fct.authenserver.entity.Role;
import com.fct.authenserver.entity.User;
import com.fct.authenserver.repository.UserRepository;
import com.fct.authenserver.requests.AuthResponse;
import com.fct.authenserver.requests.LoginRequest;
import com.fct.authenserver.requests.RegisterRequest;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final jwtService jwtService;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager; //autenticar al usuario

    public AuthResponse login(LoginRequest request) {
        authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(request.getUsername(), request.getPassword()));//Recibe credenciales
        UserDetails user = userRepository.findByUsername(request.getUsername()).orElseThrow(); //generamos token
        String token = jwtService.getToken((User) user);
        return AuthResponse.builder() //Generamos la respuesta con el token ya generado
            .token(token)
            .build();
    }

    public AuthResponse register(RegisterRequest request) {
        User user = User.builder()
            .username(request.getUsername())
            .password(passwordEncoder.encode(request.getPassword()))
            .firstname(request.getFirstname())
            .lastname(request.getLastname())
            .country(request.getCountry())
            .role(Role.USER)
            .build();

        userRepository.save(user); //Se guarda el objeto en la base de datos 

        return AuthResponse.builder() //Se obtiene el token a traves del lservidode de jwt que se retorna al controlador y luego al cleinte
            .token(jwtService.getToken(user))
            .build();
    }

}
