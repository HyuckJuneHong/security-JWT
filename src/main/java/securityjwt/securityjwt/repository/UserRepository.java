package securityjwt.securityjwt.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import securityjwt.securityjwt.entity.User;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Long> {

    Optional<User> findByEmail(String email);
}
