package securityjwt.securityjwt.entity;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import javax.persistence.*;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

@Getter
@Entity
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class User implements UserDetails {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(length = 100, nullable = false, unique = true)
    private String email;
    @Column(length = 300, nullable = false)
    private String password;

    //Embedded 삼고 싶은 프로퍼티가 Collection일 때 사용.
    //eager : 바로 가져오기
    //Builder.Default : 특정 속성에 기본값을 지정하고 싶을 때 사용.
    @ElementCollection(fetch = FetchType.EAGER)
    @Builder.Default
    private List<String> roles = new ArrayList<>();

    //GrantedAuthority : 문자열을 반환하는 getAuthority() 메소드 하나만을 가짐.
    //SimpleGrantedAuthority : GrantedAuthority의 구현체
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities(){
        return this.roles.stream() //map : 스트림 내 요소들을 하나씩 특정 값으로 변환. 이 때 값을 변환하기 위한 람다를 인자로 받음.
                .map(SimpleGrantedAuthority::new) //role -> new SimpleGrantedAuthority(role)
                .collect(Collectors.toList()); //Collectors.toList() : 스트림에서 작업한 결과를 담은 리스트로 반환
    }

    /**
     * spring security에서 사용하는 username을 가져감. (여기서 username은 email)
     * @return
     */
    @Override
    public String getUsername() {
        return email;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }
}
