package com.code.empcrud.jwtservice.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import java.util.function.Function;

@Component
public class JwtAuthenticationProvider {

    private static final String SECRET_KEY = "BWgwvfUQbvfyhCHdIlcrFDn8/dAlonrY+Kj+DJ8mhSkkFl2v+XDv/M1KK9jWO+Bi0PF88wwTmkciUO3x7/d9Mqo/lv+5qk/Fz/YM97ylIEXhAz/e/1iPC95+f3UoyiIxTYf5z2vRfKu6twhjUwMZ+9eKiLfxqkHpOqAmWZhPSr2TRL+V91I303uyoYy7cU8LiX0LVkvXvTDX4vS7wdvGPvLIUxBzC1I/Ko6n+5oHNZm+bQhoph0SEHP8ne9n6EZQ8/sMJNs8wLX7qyuanD8KhkAnn+vFTu4PTzNnV+JwUGN1L87qRiZ7CIoNwasazvgu0rvFZH5g3Hx2kVRM82zznCmbWgYdCCR0vpR1Ourj23M=";

    // Generating the token

    public String generateToken(UserDetails userDetails){
        return generateToken(new HashMap<>(), userDetails);
    }
    public String generateToken(Map<String, Object> extraClaims, UserDetails userDetails){
        return Jwts
                .builder()
                .claims(extraClaims)
                .subject(userDetails.getUsername())
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis() + 1000 * 60 *24))
                .signWith(getSignInKey())
                .compact();
    }

    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver){
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    public String getUsername(String token){
        return extractClaim(token, Claims::getSubject);
    }

    public boolean isTokenValid(String token, UserDetails userDetails){
        final String username = getUsername(token);
        return (username.equals(userDetails.getUsername()));
    }
    private boolean isTokenExpired(String token){
        return getExpirationDate(token).before(new Date());
    }

    private Date getExpirationDate(String token){
        return  extractClaim(token, Claims::getIssuedAt);
    }

    private Claims extractAllClaims(String token){
        return Jwts
                .parser()
                .verifyWith(getSignInKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    private SecretKey getSignInKey(){
        byte[] keyBytes = Decoders.BASE64.decode(SECRET_KEY);
        return Keys.hmacShaKeyFor(keyBytes);
    }
}
