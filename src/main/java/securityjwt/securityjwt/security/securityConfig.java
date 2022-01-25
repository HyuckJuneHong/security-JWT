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
                .httpBasic().disable()  //rest api만을 고려해 기본 설정은 해제 (기본 설정은 비인증시 로그인폼으로 리다이렉트)
                .csrf().disable()       //csrf 보안 토큰 disable 처리 (rest api이므로 csrf 보안이 필요없음.)
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS) //JWT 토큰 기반 인증이므로 세션 사용 안함.
                .and()
                    .authorizeRequests() // 요청에 대한 사용 권한 체크
                    .antMatchers("/*/login", "/*/logout").permitAll() //로그인, 로그아웃 창 모두 허용
                    .antMatchers("/home/**").permitAll()
                    .antMatchers("/user/**").hasRole("USER")
                    .antMatchers("/admin/**", "/user/**").hasRole("ADMIN")
                .and()
                    //지정된 필터 앞에 커스텀 필터를 추가, 즉, JwtAuthenticationFilter를 UsernamePasswordAuthenticationFilter 전에 넣음.
                    .addFilterBefore(new JwtAuthenticationFilter(jwtTokenProvider)
                        , UsernamePasswordAuthenticationFilter.class) //jwt Token 필터를 id/pw 인증 필터 전에 넣음.
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
