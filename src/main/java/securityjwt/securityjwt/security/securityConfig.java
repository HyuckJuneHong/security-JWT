package securityjwt.securityjwt.security;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import securityjwt.securityjwt.security.jwt.JwtAuthenticationFilter;
import securityjwt.securityjwt.security.jwt.JwtTokenProvider;

@RequiredArgsConstructor
@EnableWebSecurity
public class securityConfig extends WebSecurityConfigurerAdapter {

    private final JwtTokenProvider jwtTokenProvider;

    @Override
    public void configure(HttpSecurity httpSecurity) throws Exception {

        httpSecurity
                .httpBasic().disable()  //rest api만을 고려해 기본 설정은 해제
                .csrf().disable()       //csrf 보안 토큰 disable 처리 (안전하기 때문)
                .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS) //토큰 기반 인증이므로 세션 사용 안함.
                .and()
                .authorizeRequests() // 요청에 대한 사용 권한 체크
                .antMatchers("/admin/**").hasRole("ADMIN")
                .antMatchers("/user/**").hasRole("USER")
                .antMatchers("/**").permitAll()
                .and()
                .addFilterBefore(new JwtAuthenticationFilter(jwtTokenProvider)
                        , UsernamePasswordAuthenticationFilter.class) //지정된 필터 앞에 커스텀 필터를 추가
                        //즉, JwtAuthenticationFilter를 UsernamePasswordAuthenticationFilter 전에 넣음.
        ;
    }

    // 암호화에 필요한 PasswordEncoder Bean 등록
    @Bean
    public PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    // authenticationManager Bean 등록
    @Bean
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

}
