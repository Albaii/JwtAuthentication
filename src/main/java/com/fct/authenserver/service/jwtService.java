package com.fct.authenserver.service;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import com.fct.authenserver.entity.User;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;

@Service
public class jwtService {

    private static final String SECRET_KEY="586E3272357538782F413F4428472B4B6250655368566B597033733676397924";

    public String getToken(User user) {
        return getToken(new HashMap<>(), user);
    }

    private String getToken(Map<String,Object> extraClaims, User user) { //generar token
        return Jwts
            .builder() //constuir objeto
            .setClaims(extraClaims) //seteo claims
            .setSubject(user.getUsername()) //seteo username
            .setIssuedAt(new Date(System.currentTimeMillis())) //fecha que se crea
            .setExpiration(new Date(System.currentTimeMillis()+1000*60*24)) //fecha que expira
            .signWith(getKey(), SignatureAlgorithm.HS256 ) //firma //Algoritmo de encriptacion
            .compact(); //crea el objecto y lo serializa
    }

    private Key getKey() { //traemos la key para pasarle a base 64 y mandarla como key a la firma de nuestro token , con una array de bytes
        byte[] keyBytes=Decoders.BASE64.decode(SECRET_KEY);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    public String getUsernameFromToken(String token) { //Devuelve el username del claim
        return getClaim(token, Claims::getSubject);
    }

    public boolean isTokenValid(String token, UserDetails userDetails) {//Recojo el username y digo que si es ese username y si ha expirado es valido.
        final String username = getUsernameFromToken(token);
        return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
    }

    private Claims getAllClaims(String token){ //Devuelve los claims
        return Jwts
            .parserBuilder()
            .setSigningKey(getKey())
            .build()
            .parseClaimsJws(token)
            .getBody();  
    }

    public <T> T getClaim( String token, Function<Claims,T> claimsResolver){//Devuelve un claim especifico
        final Claims claims = getAllClaims(token);
        return claimsResolver.apply(claims);
    }

    private Date getExpiration(String token){ //Devuelve la fecha de expiracion del token
        return getClaim(token, Claims::getExpiration);
    }

    private boolean isTokenExpired(String token){
        return getExpiration(token).before(new Date());
    }

}
