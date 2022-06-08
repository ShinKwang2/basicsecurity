# 2장. 스프링 시큐리티 기본 API & Filter dlgo

## 1. 인증 API - 스프링 시큐리티 의존성 추가

#### 스프링 시큐리티 의존성 추가 시 일어나는 일들
* **서버가 가동되면 스프링 시큐리티의 쵝화 작업 및 보안 설정이 이루어진다.**
* 별도의 설정이나 구현을 하지 않아도 기본적인 **웹 보안 기능이 현재 시스템에 연동되어 작동함**
  * 모든 요청은 인증이 되어야 자원에 접근이 가능하다
  * 인증 방식은 폼 로그인 방식과 httpBasic 로그인 방식을 제공한다.
  * 기본 로그인 페이지를 제공한다.
  * 기본 계정 한 개를 제공한다.
    * username : user
    * password : 랜덤 문자열
<br>

#### 문제점
* 계정 추가 권한 추가, DB 연동 등
* 기본적인 보안 기능 외에 시스템에서 필요로 한느 세부적이고 추가적인 보안기능이 필요
<br>
<br>

## 2. 인증 API - 사용자 정의 보안 기능 구현

### WebSecurityConfigurerAdapter
* 스프링 시큐리티의 웹 보안 기능 초기화 및 설정
* HttpSecurity 클래스를 생성

### HttpSecurity
* 세부적인 보안 기능을 설정할 수 있는 API 제공
* 인증 API
* 인가 API

#### 인증 API
* http.formLogin()
* http.logout()
* http.csrf()
* http.httpBasic()
* http.SessionManagement()
* http.RememberMe()
* http.ExceptionHandling()
* http.addFilter()

#### 인가 API
* http.authorizeRequests()
  * .antMatchers(/admin)
  * .hasRole(USER)
  * .permitAll()
  * .authenticated()
  * .fullyAuthentication()
  * .access(hasRole(USER))
  * .denyAll()
<br>

**보안 기능을 사용자가 정의해 구현하고 싶다면, WebSecurityConfigurerAdapter 를 상속받는 클래스를 만들면 된다.**
<br>

## 3. 인증 API - Form 인증 

#### http.formLogin( ) : Form 로그인 인증 기능이 작동함

```java
protected void configure(HttpSecurity http) throws Exception {
    http.formLogin()
        .loginPage("/login.html")
        .defaultSuccessUrl("/home")
        .failureUrl("/login.html?error=ture")
        .usernameParameter("username")
        .passwordParameter("password")
        .loginProcessingUrl("/login")
        .successHandler(loginSuccessHandler())
        .failureHandler(loginFailureHandler())
}
```

* **.loginPage("/login.html")** 
  - 사용자 정의 로그인 페이지
* **.defaultSuccessUrl("/home")** 
  - 로그인 성공 후 이동 페이지
* **.failureUrl("/login.html?error=ture")** 
  - 로그인 실패 후 이동 페이지
* **.usernameParameter("username")** 
  - 아이디 파라미터명 설정
* **.passwordParameter("password")** 
  - 패스워드 파라미터명 설정
* **.loginProcessingUrl("/login")** 
  - 로그인 Form Action Url
* **.successHandler(loginSuccessHandler())** 
  - 로그인 성공 후 핸들러
* **.failureHandler(loginFailureHandler())** 
  - 로그인 실패 후 핸들러
<br>
<br>

## 4. 인증 API - UsernamePasswordAuthenticationFilter

#### LoginForm 인증의 흐름
1. Request
2. **UsernamePasswordAuthenticationFilter** 사용
3. **AntPathRequestMatcher(/login)**
   * 요청 정보가 매칭되는지 확인
   * No -> chain.doFilter
   * Yes
4. **Authentication 객체 생성** (Username + Password)
   * 인증
5. **AuthenticationManager(인증관리자**) 에 인증 처리
   * 내부적으로 AuthenticationProvider 에 위임
6. **AuthenticationProvider**
   * 인증실패 - AuthenticationException - 다시 Filter로 감
   * 인증성공 - Authentication 객체를 만듬(user + authorities), AuthenticationManager 로 다시 리턴
7. **AuthenticationManager가 Authentication (User + Authorities) 를 Filter로 전달**
9. Filter는 **SecurityContext 에 인증 객체를** 저장
10. SuccessHandler :  인증 성공 이후 작업들 실행
<br>

#### FilterChainProxy

* 필터를 관리하는 클래스, 여기서 UsernamePasswordAuthenticationFilter 도 관리한다.

* 요청을 필터들에 전달하면서 인증이나 인가처리를 지시
<br>

## 5. 인증 API - Logout, LogoutFilter

#### Logout
* 세션 무효화
* 인증토큰 삭제, SecurityContext 삭제 
* 쿠키 정보 삭제
* 로그인 페이지로 리다이렉트
<br>

#### http.logout() : 로그아웃 기능이 작동함

```java
protected void configure(HttpSecurity http) throws Exception {
    http.logout()
        .logoutUrl("/logout")
        .logoutSuccessUrl("/login")
        .deleteCookie("JSESSIONID", "remember0me")
        .addLogoutHandler(logoutHandler())
        .logoutSuccessHandler(logoutSuccessHandler())
}
```

* **http.logout()**
  - 로그 아웃 처리
* **.logoutUrl("/logout")**
  - 로그아웃 처리 URL
* **.logoutSuccessUrl("/login")**
  - 로그아웃 성공 후 이동페이지
* **.deleteCookie("JSESSIONID", "remember0me")**
  - 로그아웃 후 쿠키 삭제
* **.addLogoutHandler(logoutHandler())**
  - 로그아웃 핸들러
* **.logoutSuccessHandler(logoutSuccessHandler())**
  - 로그아웃 성공 후 핸들러

<br>

### Logout 의 흐름

1. Request(일반적으로 POST 방식)
2. **LogoutFilter**
3. **AntPathRequestMatcher(/logout)**
   * 요청 정보가 매칭되는지 확인 
   * No -> chain.doFilter
   * Yes
4. LogoutFilter가 **SecurityContext 에서 인증 객체(Authentication)를 꺼내온다.**
5. LogoutFilter 가 가지고 있는 Logout 핸들러 중에 **SecurityContextLogoutHandler** 에게 인증 객체 전달
6. **SecurityContextLogoutHandler** 는 아래와 같은 일을 한다.
   - 세션 무효화
   - 쿠키 삭제
   - SecurityContextHolder.clearContext( )

7. LogoutHandler 가 성공적으로 종료가 되면, LogoutFilter는 **SimpleUrlLogoutSuccessHandler** 를 호출해서 로그인 페이지로 이동
<br>
<br>

## 6. 인증 API - Remember Me 인증

### Remember Me 인증
1. 세션이 완료되고 웹 브라우저가 종료된 후에도 어플리케이션이 사용자를 기억하는 기능
2. Remember-Me 쿠키에 대한 Http 요청을 확인 후 토큰 기반 인증을 사용해 유효성을 검사하고 토큰이 검증되면 사용자는 로그인 된다.
3. 사용자 라이프 사이클
   * 인증 성공(Remember-Me 쿠키 설정)
   * 인증 실패(쿠키가 존재하면 쿠키 무효화)
   * 로그아웃(쿠키가 존재하면 쿠키 무효화)

#### http.rememberMe( ) : rememberMe 기능이 작동함
```java
protected void configure(HttpSecurity http) throws Exception {
    http.rememberMe()
        .rememberMeParameter("remember")
        .tokenValiditySeconds(3600)
        .alwaysRemember(true)
        .userDetailsService(userDetailsService)
}
```
* **.rememberMeParameter("remember")**
  * 파라미터 명을 변경할 수 있음
  * 기본 파라미터명은 remember-me
* **.tokenValiditySeconds(3600)**
  * 초 단위로 리멤버미 쿠키의 만료시간 설정
  * 기본값은 14일
* **.alwaysRemember(true)**
  * true로 설정하면 리멤버 미 기능이 활성화되지 않아도 항상 실행
  * 기본값은 false
* **.userDetailsService(userDetailsService)**
  * remember-me 기능을 수행할 때, 사용자 계정을 조회하는 과정이 있는데 그때 필요한 클래스
  * **리멤버미 인증을 할 때 반드시 필욯나 설정**
br>

## 7. 인증 API - RememberMeAuthenticationFilter

### Remember Me 인증의 흐름

1. Request
2. **RememberMeAuthenticationFilter**
   * **작동 조건 1 : 인증 객체가 없는 경우**
      * 사용자 세션이 만료되었거나 끊겨서 세션 안에서 SecurityContext 를 찾지 못하고, 인증 객체(Authentication)도 없는 경우
      * 즉, **인증 객체가 null 인 경우에만 작동**
      * ex) 세션 타임 아웃(세션 만료)이나 브라우저 종료(세션 끊김)로 세션이 활성화되지 않는 경우
  
    * **작동 조건 2 : 사용자가 rememberMe 쿠키를 가지고 있는 경우**
      * 사용자가 최초 Form 인증을 받을 시 RememberMe 쿠키를 발급 받았을 때

3. **RememberMeServices 인터페이스**
   * **TokenBasedRememberMeServices**
     * 메모리에서 제작한 토큰과 클라이언트의 토큰을 비교해서 인증 처리(기본 14일 만료)
   * **PersistentTokenBasedRememberMeServices**
     * DB에 토큰을 저장하고 클라이언트의 토큰을 비교해서 인증 처리(영구적인 방식)

4. **Token Cookie 추출**
5. **Token(rememberMe Token) 이 존재하는가?**
   * No -> chain.doFilter
   * Yes
6. **Decode Token(정상 유무 판단)**
   * No -> Exception
   * Yes
7. **Token 이 서로 일치하는가?**
   * No -> Exception
   * Yes
8. **User 계정이 일치하는가?**
   * No -> Exception
   * Yes
9. 새로운 인증 객체(Authentication) 생성
10. AuthenticationManager 에게 전달
<br>
<br>

## 8. 인증 API - AnonymousAuthenticationFilter

어떤 사용자가 인증을 받게되면, 세션에 인증을 받은 사용자의 인증 객체를 저장하게 된다.

저장한 다음, 사용자가 어떤 자원에 접근하려고 하면 먼저 세션에서 그 사용자가 인증한 그 때의 객체가 존재하지 않는지(null인지 아닌지) 여부를 판단

AnonymousAuthenticationFilter 도 동작방식이 동일하지만, null로 처리하는 것이 아니라 **익명 사용자용 인증 객체를 만들어서 처리한다.**

* **익명 사용자 인증 처리 필터**
* **익명 사용자와 인증 사용자를 구분해서 처리하기 위한 용도로 사용**
* **화면에서 인증 여부를 구현할 때 isAnonymous( ) 와 isAuthenticated( ) 로 구분해서 사용**
* **인증객체를 세션에 저장하지 않는다.**
<br>

#### AnonymousAuthenticationFiler 의 흐름

1. Request
2. **AnonymousAuthenticationFilter** 
3. 먼저 인증 객체가 존재하는지 여부를 판단
   * Yes -> chain.doFiler
   * No
4. **AnonymousAuthenticationToken 인증 객체 생성**
   * 일반적인 토큰이 없다면, null 로 처리하지만
   * AnonymousAuthenticationFilter는 위와 같이 "익명 인증 객체" 생성
5. SecurityContextHolder 의 **SecurityContext에 AnonymousAuthenticationToken 저장**

<br>
<br>

## 9. 인증 API - 동시 세션 제어 / 세션고정보호 / 세션 정책

### 1) 동시세션 제어

동일한 계정으로 인증을 받을 때, 생성되는 세션의 허용 개수가 초과되었을 경우 어떻게 세션을 계속적으로 초과하지 않고 유지하는지에 대한 제어

**SpringSecurity는 두 가지 전략으로, 동시적 세션 제어 제공**

1. **이전 사용자 세션 만료**
   * 사용자 1 - 로그인 / 세션 생성
   * 사용자 2 - 로그인 / 세션 생성
   * 서버 - 이전 사용자(사용자 1) 세션 만료 설정
   * 사용자 1 이 링크를 접속하면, 세션 만료
<br>

2. **현재 사용자 인증 실패**
   * 사용자 1 - 로그인 / 세션 생성
   * 사용자 2 - 로그인 / 인증 예외 발생
<br>

#### http.sessionManagement( ) : 세션 관리 기능이 작동함
```java
protected void configure(HttpSecurity http) throws Exception {
    http.sessionManagement()
        .maximumSessions(1)
        .maxSessionsPreventsLogin(true)
        .invalidSessionUrl("/invalid")
        .expriedUrl("/expired");
}
``` 

* **.maximumSessions(1)**
  * 최대 허용 가능 세션 수
  * -1 : 무제한 로그인 세션 허용
* **.maxSessionsPreventsLogin(true)**
  * 동시 로그인 차단함(현제 사용자 인증 실패)
  * 기본 값 : false - 기본 세션 만료(이전 사용자 세션 만료)
* **.invalidSessionUrl("/invalid")**
  * 세션이 유효하지 않을 때 이동 할 페이지
* **.expiredUrl("/expired")**
  * 세션이 만료된 겅우 이동 할 페이지

.invalidSessionUrl 과 .expiredUrl 을 동시에 사용할 때는 **.invalidSessionUrl에 우선 순위**


--- 
#### 참고 사항.

**.maximumSessions(1)** 와 
**.maxSessionsPreventsLogin(true)**, 
**.expiredUrl("/expired")** 반환형은?

**SessionManagementConfigurer\<HttpSecurity>.ConcurrencyControlConfigurer** 이다.

그렇다면 **.invalidSessionUrl("/invalid")** 반환형은?
**SessionManagementConfigure\<HttpSecurity>** 이다.

**따라서... 순서는 .invalidSessionUrl을 먼저 써야한다.**
위 예제와 같이 쓰면 .invalidSessionUrl 은 쓸 수 없으니 컴파일 에러!!!

아래와 같이 적용해야한다.

```java
protected void configure(HttpSecurity http) throws Exception {
    http.sessionManagement()
        .invalidSessionUrl("/invalid")
        .maximumSessions(1)
        .maxSessionsPreventsLogin(true)
        .expriedUrl("/expired");
}
``` 

---

<br>

### 2) 세션 고정 보호

공격자의 세선 탈취 혹은 공유로부터 사용자를 보호하는 정책

* **세션 고정 공격이란**?
  * 공격자가 서버에 접속해서 JSSESSIONID를 발급받아 사용자에게 자신이 발급받은 세션 쿠키를 심어놓게 되면, 사용자가 세션쿠키로 로그인 시도했을 경우 **공격자는 같은 쿠키값으로 인증되어 있기 때문에 사용자 정보를 공유하게 된다.
* **해결책 : 매번 인증에 성공할 때마다, 새로운 세션을 생성하고 새로운 세션 ID를 만드는 것**

```java
protected void configure(HttpSecurity http) throws Exception {
    http.sessionManagement()
        .sessionFixation().changeSessionId()
}
```

* **.changeSessionId()**
  * 세션 ID만 변경
  * 서블릿 3.1 이상에서 기본 값
* **migrateSession()**
  * 새로운 세션을 생성, 새로운 세션 ID 발급
  * 서블릿 3.1 이하에서 기본 값

changeSessionId 와 migrateSession은 세션에서 설정한 여러 설정값들을 그대로 사용

* **newSession()**
  * 새로운 세션을 생성, 새로운 세션 ID 발급
  * 차이점은 **세션의 설정 값 유지 X, 새로 설정해야 함**
<br>

### 3) 세션 정책
```java
protected void configure(HttpSecurity Http) throws Exception {
    http.sessionManagemnet()
        .sessionCreationPolicy(SessionCreationPolicy.If_Required)
}
```

* **SessionCreationPoliciy.Always**
  * 스프링 시큐리티가 항상 세션 생성
* **SessionCreationPoliciy.If_Required**
  * 스프링 시큐리티가 필요 시 생성(기본값)
* **SessionCreationPoliciy.Never**
  * 스프링 시큐리티가 생성하지 않지만 이미 존재하면 사용
* **SessionCreationPoliciy.Stateless**
  * 스프링 시큐리티가 생성하지 않고 존재해도 사용하지 않음
  * JWT 인증 방식을 이용할 때 주로 사용(세션 없이)

<br>

## 10. 인증 API - SessionManagemnetFilter / ConcurentSessionFilter

### 1) SessionManagementFilter
* **세션 관리**
  * 인증 시 사용자의 세션정보를 등록, 조회, 삭제 등의 세션 이력을 관리
* **동시적 세션 제어**
  * 동일 계정으로 접속이 허용되는 최대 세션 수를 제한
* **세션 고정 보호**
  * 인증 할 때마다 세션쿠키를 새로 발급하여 공격자의 쿠키 조작을 방지
* **세션 생성 정책**
  * Always, If_Required, Never, Stateless 
<br>

### 2) ConcurrentSessionFilter
* **매 요청 마다 현재 사용자의 세션 만료 여부 체크**
* **세션이 만료되었을 경우 즉시 만료 처리**
* **session.isExpired( ) == true**
  * 로그아웃 처리
  * 즉시 오류 페이지 응답 - "This session has been expired"


### SessionManagementFilter 와 ConcurrentSessionFilter 의 흐름

1. 이전 사용자의 로그인
2. 사용자 2의 Request
3. **SessionManagementFilter** 이전 사용자의 세션을 만료시키는 전략 이용(최대 세션 허용 개수 초과되었을 경우)
   * session.expireNow( )
4. 이전 사용자의 Request
5. **ConcurrentSessionFilter**
   * 매 요청마다 세션 만료 여부 체크
   * session.isExpired( )
   * true 이면 Logout
6. Logout 및 오류 페이지 응답
<br>
<br>

## 11. 인가 API - 권한 설정 및 표현식

### 1) 권한 설정

#### 선언적 방식
* URL 방식
```java
http.antMatchers("/users/**").hasRole("USER")
```

* Method 방식 (애노테이션)
```java
@PreAuthorize("hasRole('USER')")
public void user( ) { 
    System.out.println("user")
}
```

#### 동적 방식 - DB 연동 프로그래밍
* URL
* Method


##### 권한 설정 예시
```java
@Override
protected void configure(HttpSecurity http) throws Exception {
    http
        .antMatcher("/shop/**")
        .authorizeRequests()
            .antMatchers("/shop/login", "/shop/users/**").permitAll()
            .antMatchers("/shop/mypage").hasRole("USER")
            .antMatchers("/shop/admin/pay").access("hasRole('ADMIN')");
            .antMatchers("/shop/admin/**").access("hasRole('ADMIN') or hasRole('SYS')";
            .anyRequest().authenticated();
}
```
* 주의사항 - 설정 시 구체적인 경로가 먼저 오고, 그것보다 큰 범위의 경로가 뒤에 오도록 해야 한다.
* 위에서 아래로 내려가기 때문에, 아래의 예를 살펴보자.
```java
.antMatchers("/shop/admin/pay").access("hasRole('ADMIN')");
.andMatchers("/shop/admin/**").access("hasRole('ADMIN') or hasRole('SYS')");
```
* 만약 반대로 되어있다면, pay 자원에도 SYS 롤로 들어올 수 있다.
<br>

### 2) 인가 API - 표현식

#### 인증과 관련된 표현식 
* **authenticated( )**
  * 인증된 사용자의 접근을 허용
* **fullyAuthenticated( )**
  * 인증된 사용자의 접근을 허용, rememberMe 인증 제외
* **permitAll( )**
  * 무조건 접근을 허용
* **denyAll( )**
  * 무조건 접근을 허용하지 않음
* **anonymous( )**
  * 익명 사용자만의 접근을 허용(**익명 사용자용**)
* **rememberMe( )**
  * 기억하기를 통해 인증된 사용자의 접근을 허용
* **access(String)**
  * 주어진 SpEL 표현식의 평가 결과가 true 이면 접근을 혀용
<br>

#### 권한과 관련된 표현식
* **hasRole(String)**
  * 사용자가 주어진 역할이 있다면 접근을 허용
  * prefix 생략
  * ex) Role.USER 라면 "USER"만
* **hasAuthority(String)**
  * 사용자가 주어진 권한이 있다면 접근을 허용
  * prefix 를 넣어야함
  * ex) Role.USER
* **hasAnyRole(String...)**
  * 사용자가 주어진 어떠한 역할이라도 있다면 접근을 허용
* **hasAnyAuthority(String...)**
  * 사용자가 주어진 권한 중 어떠한 것이라도 있다면 접근을 허용
* **hasAddress(String)**
  * 주어진 IP 로부터 요청이 왔다면 접근을 허용 

<br>
<br>

## 12. 예외 처리 및 요청 캐시 필터

### ExceptionTranslationFilter & RequestCacheAwareFilter

##### 필터의 순서
>ExceptionTranslationFilter -> FilterSecurityInterceptor(맨 마지막에 위치한 필터)
>
>FilterSecurityInterceptor가 던지는 인증 예외와 인가 예외는 자기를 호출한 ExceptionTranslationFilter를 던짐(throw)
>
>따라서 ExceptionTranslationFilter 가 AuthenticationException(인증 예외)와 AccessDeniedException 을 어떻게 처리하는지가 관건

### 1) ExceptionTranslationFilter

#### AuthenticationException
* **인증 예외 처리**
  * **AuthenticationEntryPoint 호출**
    * 로그인 페이지 이동, 401 오류 코드 전달 등
  * **인증 예외가 발생하기 전의 요청 정보를 저장**
    * **RequestCache** - 사용자의 이전 요청 정보를 세션에 저장하고 이를 꺼내 오는 캐시 메카니즘
      * **SavedRequest** - 사용자가 요청했던 request 파라미터 값들, 그 당시의 헤더값들 등이 저장

#### AccessDeniedException
* **인가 예외 처리**
  * **AccessDeniedHandler 에서 예외 처리하도록 제공**
<br>


#### http.exceptionHandling( ) : 예외처리 기능이 작동함
```java
protected void configure(HttpSecurity http) throws Exceptions {
  http.exceptionHandling()
      .authenticationEntryPoint(authenticationEntryPoint()) //인증실패시 처리
      .accessDeniedHandler(accessDeniedHandler()) // 인가실패시 처리
}
```
<br>
<br>

## 13. 사이트 간 요청 위조 - CSRF, CsrfFilter

### CSRF(사이트 간 요청 위조) : Cross Site Request Forgery


### CsrfFilter
  * 모든 요청에 랜덤하게 생성된 토큰을 HTTP 파라미터로 요구
  * 요청 시 전달되는 토큰 값과 서버에 저장된 실제 값과 비교한 후 만약 일치하지 않으면 요청은 실패

**Client**
```html
\<input type="hidden" name="${_csrf.parameterName}" value ="${_csrf.token}">
``` 
* HTTP 메소드 : PATCH, POST, PUT, DELETE

**SpringSecurity**
* http.csrf( ) : 기본 활성화되어 있음
* http.csrf( ).disabled( ) : 비활성화