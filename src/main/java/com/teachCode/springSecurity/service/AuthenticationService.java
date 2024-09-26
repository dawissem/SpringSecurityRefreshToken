package com.teachCode.springSecurity.service;

import com.teachCode.springSecurity.dao.request.SignUpRequest;
import com.teachCode.springSecurity.dao.request.SingninRequest;
import com.teachCode.springSecurity.dao.request.response.JwtAuthenticationResponse;

public interface AuthenticationService {

    JwtAuthenticationResponse SignUp(SignUpRequest request);
    JwtAuthenticationResponse SignIn(SingninRequest request);



}
