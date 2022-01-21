package securityjwt.securityjwt.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import securityjwt.securityjwt.entity.User;

public interface UserRepository extends JpaRepository<User, Long> {
}
