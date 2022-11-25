package io.security.basicsecurity.repository;

import io.security.basicsecurity.domain.Account;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UserRepository extends JpaRepository<Account,Long> {
    Optional<Account> findByUserName(String username);
}
