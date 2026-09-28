package com.github.highcumontoa.tokenrotationaccesscontroljava.web;

import com.github.highcumontoa.tokenrotationaccesscontroljava.model.Permission;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

@Target(ElementType.METHOD)
@Retention(RetentionPolicy.RUNTIME)
public @interface RequiredPermission {
    Permission value();
}
