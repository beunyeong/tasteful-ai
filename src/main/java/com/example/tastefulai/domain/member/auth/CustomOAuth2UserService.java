package com.example.tastefulai.domain.member.auth;

import com.example.tastefulai.domain.member.entity.Member;
import com.example.tastefulai.domain.member.enums.GenderRole;
import com.example.tastefulai.domain.member.enums.MemberRole;
import com.example.tastefulai.domain.member.repository.MemberRepository;
import com.example.tastefulai.global.util.JwtProvider;
import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import java.util.Map;

@Service
@RequiredArgsConstructor
public class CustomOAuth2UserService extends DefaultOAuth2UserService {

    private final MemberRepository memberRepository;

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) {
        OAuth2User oAuth2User = super.loadUser(userRequest);

        String registrationId = userRequest.getClientRegistration().getRegistrationId(); // google, kakao
        Map<String, Object> attributes = oAuth2User.getAttributes();

        JwtProvider.OAuth2UserInfo userInfo = JwtProvider.OAuthAttributes.extract(registrationId, attributes);
        String email = userInfo.getEmail();

        Member member = memberRepository.findByEmail(email)
                .orElseGet(() -> memberRepository.save(
                        new Member(
                                MemberRole.USER,
                                email,
                                "oauth2_default_password",
                                userInfo.getNickname(),
                                0,
                                GenderRole.OTHER,
                                null,
                                userInfo.getProvider()
                        )
                ));
        return new CustomOAuth2User(member, attributes);
    }


}
