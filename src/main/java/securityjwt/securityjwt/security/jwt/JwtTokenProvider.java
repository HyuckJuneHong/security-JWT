package securityjwt.securityjwt.security.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Component;

import javax.annotation.PostConstruct;
import javax.servlet.http.HttpServletRequest;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Date;
import java.util.List;

//실제 이 컴포넌트를 이용하는 것은 인증 작업을 진행하는 Filter
//때문에, 이 필터는 검증이 끝난 JWT로부터 유저정보를 받아와서
//UsernamePasswordAuthenticationFilter 로 전달해야 할 것
@RequiredArgsConstructor
@Component
public class JwtTokenProvider {

    private String secretKey = "webfirewood";

    //토큰 유효시간 30분
    private long tokenValidTime = 30 * 60 * 1000L;

    //유저 정보를 UserDetails 타입으로 Spring Security 한테 제공하는 역할
    //UserDetail : 애플리케이션이 가지고 있는 유저 정보와 spring Security가 사용하는 Authenticaiton 객체 사이의 어댑터
    private final UserDetailsService userDetailsService;

    /** init(), @PostConstruct
     * init() : 객체 초기화, secretKey를 Base64로 인코딩.
         * @PostConstruct : 의존성 주입이 이루어진 후 초기화를 수행하는 메서드.
     *      -> 즉, 클래스가 service(로직을 탈 때? 로 생각 됨)를 수행하기 전에 발생.
     *      -> 때문에, 이 메서드는 다른 리소스에서 호출되지 않는다해도 수행
     */
    //
    @PostConstruct
    protected void init(){
        secretKey = Base64.getEncoder()
                        .encodeToString(secretKey.getBytes(StandardCharsets.UTF_8));
    }

    //JWT 토큰 생성
    public String createToken(String userPk, List<String> roles) {

        //페이로드 : 실제로 전달할 정보
        Claims claims = Jwts.claims().setSubject(userPk); // JWT payload에 저장되는 정보단위
        claims.put("roles", roles); // 정보는 key / value 쌍으로 저장된다.
        Date now = new Date();

        //JWT : JSON 객체를 암호화 하여 만든 문자열 값으로 위변조가 어려운 정보
        return Jwts.builder()
                .setClaims(claims) // 정보 저장
                .setIssuedAt(now)  // 토큰 발행 시간 정보
                .setExpiration(new Date(now.getTime() + tokenValidTime)) // 만료 시간 설정
                .signWith(SignatureAlgorithm.HS256, secretKey) // 사용할 암호화 알고리즘, 서명에 들어갈 secret 값 세팅
                .compact();
    }

    // JWT 토큰에서 인증 정보 조회
    public Authentication getAuthentication(String token) {

        //loadUserByUsername : 인증의 주체에 대한 정보를 가져오는 메소드
        UserDetails userDetails = userDetailsService.loadUserByUsername(this.getUserPk(token));
        return new UsernamePasswordAuthenticationToken(userDetails, "", userDetails.getAuthorities());
    }

    // 토큰에서 회원 정보 추출
    public String getUserPk(String token) {
        return Jwts.parser().setSigningKey(secretKey).parseClaimsJws(token).getBody().getSubject();
    }

    // Request의 Header에서 token 값을 가져옵니다. "X-AUTH-TOKEN" : "TOKEN값'
    public String resolveToken(HttpServletRequest request) {
        return request.getHeader("X-AUTH-TOKEN");
    }

    // 토큰의 유효성 + 만료일자 확인
    public boolean validateToken(String jwtToken) {

        try {
            Jws<Claims> claims = Jwts.parser().setSigningKey(secretKey).parseClaimsJws(jwtToken);
            return !claims.getBody().getExpiration().before(new Date());
        } catch (Exception e) {
            return false;
        }
    }
}

