package com.github.highcumontoa.tokenrotationaccesscontroljava.config;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;

/**
 * Web/安全相关配置入口。访问控制由各控制器显式调用
 * {@code AccessControlService.requirePermission(...)} 完成（便于在响应中
 * 返回 jti 等可解释信息），因此这里只启用配置属性绑定。
 */
@Configuration
@EnableConfigurationProperties(SecurityProperties.class)
public class WebConfig {
}
