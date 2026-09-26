package com.github.xingjianluo.multitenantaccessguardjava.web;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.time.Clock;

/** 通用 Bean：时钟可替换，便于测试时间相关语义。 */
@Configuration
public class GuardConfig {

    @Bean
    public Clock clock() {
        return Clock.systemUTC();
    }
}
