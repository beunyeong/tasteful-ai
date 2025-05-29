package com.example.tastefulai.global.util;

import com.example.tastefulai.domain.member.enums.ProviderType;

import java.util.Map;

public class GoogleUserInfo implements JwtProvider.OAuth2UserInfo {
    private final Map<String, Object> attributes;

    public GoogleUserInfo(Map<String, Object> attributes) {
        this.attributes = attributes;
    }

    public String getEmail() {
        return (String) attributes.get("email");
    }

    public String getNickname() {
        return (String) attributes.get("name");
    }

    public ProviderType getProvider() {
        return ProviderType.GOOGLE;
    }

}