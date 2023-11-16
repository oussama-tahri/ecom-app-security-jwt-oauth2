package com.tahrioussama.securityservice.web;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
public class RestTest {

    @GetMapping("/test")
    @PreAuthorize("hasAuthority('SCOPE_ADMIN')")
    public Map<String,Object> getMethod(Authentication authentication) {
        return Map.of(
                "Range Rover","Baby Velar",
                "message","Data test",
                "username",authentication.getName(),
                "authorities",authentication.getAuthorities()
        );
    }
}
