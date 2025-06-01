package com.example.tastefulai;

import com.example.tastefulai.domain.member.auth.CustomOAuth2UserService;
import com.example.tastefulai.domain.member.auth.OAuth2SuccessHandler;
import com.example.tastefulai.global.config.filter.JwtAuthFilter;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.data.redis.listener.RedisMessageListenerContainer;

@SpringBootTest
class TastefulAiApplicationTests {

    @Test
    void contextLoads() {
    }

    @MockBean
    private RedisMessageListenerContainer redisMessageListenerContainer;

    @MockBean
    private JwtAuthFilter jwtAuthFilter;

    @MockBean
    private OAuth2SuccessHandler oAuth2SuccessHandler;

    @MockBean
    private CustomOAuth2UserService customOAuth2UserService;


}
