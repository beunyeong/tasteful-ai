package com.example.tastefulai.global.util;

import com.example.tastefulai.domain.member.entity.Member;
import com.example.tastefulai.domain.member.enums.ProviderType;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.Map;

@Component
@RequiredArgsConstructor
@Slf4j
public class JwtProvider {

    @Value("${jwt.secret}")
    private String secret;

    @Getter
    @Value("${jwt.access-token-expiration}")
    private long accessTokenExpiryMillis;

    @Getter
    @Value("${jwt.refresh-token-expiration}")
    private long refreshTokenExpiryMillis;

    public String generateToken(String email, long expiryMillis) {
        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + expiryMillis);

        return Jwts.builder()
                .setSubject(email)
                .setIssuedAt(now)
                .setExpiration(expiryDate)
                .signWith(Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8)), SignatureAlgorithm.HS256)
                .compact();
    }

    public boolean validateToken(String token) {
        try {
            Jwts.parser()
                    .setSigningKey(Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8)))
                    .build()
                    .parseClaimsJws(token);
            return true;
        } catch (Exception exception) {
            log.error("JWT 검증 실패: {}", exception.getMessage());
            return false;
        }
    }

    public String getEmailFromToken(String token) {
        return Jwts.parser()
                .setSigningKey(Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8)))
                .build()
                .parseClaimsJws(token)
                .getBody()
                .getSubject();
    }

    public String generateAccessToken(String email) {
        return generateToken(email, accessTokenExpiryMillis);
    }

    public String generateRefreshToken(String email) {
        return generateToken(email, refreshTokenExpiryMillis);
    }

    public class OAuthAttributes {
        public static OAuth2UserInfo extract(String provider, Map<String, Object> attributes) {
            return switch (provider) {
                case "google" -> new GoogleUserInfo(attributes);
//                case "kakao" -> new KakaoUserInfo(attributes);
                default -> throw new IllegalArgumentException("Unknown provider: " + provider);
            };
        }
    }

    public interface OAuth2UserInfo {
        String getEmail();
        String getNickname();
        ProviderType getProvider();
    }

    public String generateAccessToken(Member member) {
        Date now = new Date();
        Date expiry = new Date(now.getTime() + accessTokenExpiryMillis);
        return Jwts.builder()
                .setSubject(member.getEmail())
                .claim("memberId", member.getId())
                .claim("role", member.getMemberRole().name())
                .setIssuedAt(now)
                .setExpiration(expiry)
                .signWith(SignatureAlgorithm.HS256, secret.getBytes())
                .compact();
    }

    public String generateRefreshToken(Member member) {
        Date now = new Date();
        Date expiry = new Date(now.getTime() + refreshTokenExpiryMillis);

        return Jwts.builder()
                .setSubject(member.getEmail())
                .setIssuedAt(now)
                .setExpiration(expiry)
                .signWith(SignatureAlgorithm.HS256, secret.getBytes())
                .compact();
    }

}
