package com.example.service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.*;
import java.util.function.Function;

@Service
public class JwtAuthService {

    private static final String SECRET_KEY = "423F4428472B4B6250655368566D597133743677397A244326462948404D6351";
    public String extractUsername(String token) {
        return extractClaims(token, Claims::getSubject);
    }
    public boolean isTokenValid(String token, UserDetails user) {
        final String username = extractUsername(token);
        return username.equals(user.getUsername()) &&!isTokenExpired(token);

    }
    private boolean isTokenExpired(String token){
        return extractExpiration(token).before(new Date());
    }
    private Date extractExpiration(String token) {
        return extractClaims(token, Claims::getExpiration);
    }
    public String generateToken(UserDetails userDetails){
        return this.generateToken(new HashMap<>(), userDetails);
    }
    public String generateToken(
            Map<String, Object> extraClaims,
            UserDetails userDetails) {
        return Jwts
                .builder()
                .setClaims(extraClaims)
                .setSubject(userDetails.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + 100*60*24))
                .signWith(getSigningKey(), SignatureAlgorithm.HS256)
                .compact();
    }
    public  <T> T extractClaims(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }
    private Claims extractAllClaims(String token) {
        return Jwts
                .parserBuilder()
                .setSigningKey(getSigningKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }
    private Key getSigningKey() {
        byte[] keyBytes = Decoders.BASE64.decode(SECRET_KEY);
        return Keys.hmacShaKeyFor(keyBytes);
    }
}
