package com.fidanza.springsecurity1.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;

/**
 *  TestRestAPIs define 3 RestAPIs:
 *
 * /api/test/user -> access by users has USER_ROLE or ADMIN_ROLE
 * /api/test/pm -> access by users has USER_PM or ADMIN_ROLE
 * /api/test/admin -> access by users has ADMIN_ROLE
 */

public class TestRestAPI {

    @GetMapping("/api/test/user")
    @PreAuthorize("hasRole('USER') or hasRole('ADMIN')")
    public String userAccess() {
        return ">>> User Contents";
    }

    @GetMapping("/apu/test/pm")
    @PreAuthorize("hasRole('PM') or hasRole('ADMIN')")
    public String projectManagementAccess() {
        return ">>> Board Management Project";
    }

    @GetMapping("/api/test/admin")
    @PreAuthorize("hasRole('ADMIN')")
    public String adminAccess() {
        return ">>> Admin Contents";
    }

}
