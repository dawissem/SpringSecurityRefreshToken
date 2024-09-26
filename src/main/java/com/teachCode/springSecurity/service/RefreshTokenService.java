package com.teachCode.springSecurity.service;

import com.teachCode.springSecurity.entities.RefreshToken;
import com.teachCode.springSecurity.entities.User;

import java.util.Optional;

public interface RefreshTokenService {

    public RefreshToken createRefreshToken(User user);
    public Optional<RefreshToken> findByToken(String token);
    public RefreshToken verifyExpiration(RefreshToken token);
    public void deleteByUser(User user);
}
