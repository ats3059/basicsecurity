package io.security.basicsecurity.domain;

import lombok.Data;

@Data
public class AccountDto {
    private String username;
    private String password;
    private String age;
    private String role;
}
