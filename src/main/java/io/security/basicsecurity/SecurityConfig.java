package io.security.basicsecurity;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.AuthenticationEntryPointFailureHandler;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;

@Configuration
@EnableWebSecurity
@Order(0)
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    /**     SecurityConfig : 사용자 정의 보안 설정 클래스
     *      WebSecurityConfigurerAdapter : 스프링 시큐리티의 웹 보안 기능 초기화 및 설정
     *      HttpSecurity : 세부적인 보안 기능을 설정할 수 있는 API 제공
     * */

    @Autowired
    UserDetailsService userDetailsService;

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication().withUser("user").password("{noop}1111").roles("USER");
        auth.inMemoryAuthentication().withUser("sys").password("{noop}1111").roles("SYS");
        auth.inMemoryAuthentication().withUser("admin").password("{noop}1111").roles("ADMIN","SYS","USER");
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {

        http    /** 구체적인 범위가 위에 와야 한다.  **/
                .authorizeRequests()
                .antMatchers("/login").permitAll()
                .antMatchers("/user").hasAnyRole("USER")
                .antMatchers("/admin/**").access("hasRole('ADMIN') or hasRole('SYS')")
                .antMatchers("/admin/pay").hasAnyRole("ADMIN")
                .anyRequest().authenticated();

        http
            .exceptionHandling()
//            .authenticationEntryPoint(new AuthenticationEntryPoint() {
//                @Override
//                public void commence(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, AuthenticationException e) throws IOException, ServletException {
//                    httpServletResponse.sendRedirect("/login");
//                }
//            })
            .accessDeniedHandler(new AccessDeniedHandler() {
                @Override
                public void handle(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, AccessDeniedException e) throws IOException, ServletException {
                    httpServletResponse.sendRedirect("/denied");
                }
            });


        /**
         *      아래 formLogin으로 설정하는 url들은
         *      실제 html form의 action, href등의 url과 동일해야 한다.
         * */

        http
                .formLogin()
                .successHandler(new AuthenticationSuccessHandler() { /** 로그인 성공시 이전에 머물던 페이지로 이동 **/
                    @Override
                    public void onAuthenticationSuccess(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, Authentication authentication) throws IOException, ServletException {
                        RequestCache requestCache = new HttpSessionRequestCache();
                        SavedRequest savedRequest = requestCache.getRequest(httpServletRequest, httpServletResponse);
                        String redirectUrl = savedRequest.getRedirectUrl();
                        if("".equals(redirectUrl) || redirectUrl==null) httpServletResponse.sendRedirect("/");
                        httpServletResponse.sendRedirect(redirectUrl);
                    }
                });
//                .loginPage("/loginPage")
//                .defaultSuccessUrl("/")
//                .failureUrl("/login")
//                .usernameParameter("userId")
//                .passwordParameter("password")
//                .loginProcessingUrl("/login-proc")
//                .successHandler(new AuthenticationSuccessHandler() {
//                    @Override
//                    public void onAuthenticationSuccess(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, Authentication authentication) throws IOException, ServletException {
//                        System.out.println("authentication = " + authentication.getName());
//                        httpServletResponse.sendRedirect("/");
//                    }
//                })
//                .failureHandler(new AuthenticationFailureHandler() {
//                    @Override
//                    public void onAuthenticationFailure(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, AuthenticationException e) throws IOException, ServletException {
//                        System.out.println("e.getMessage() = " + e.getMessage());
//                        httpServletResponse.sendRedirect("/login");
//                    }
//                })
//                .permitAll();
        http
                .logout()
                .logoutUrl("/logout")
                .logoutSuccessUrl("/login")
                .addLogoutHandler(new LogoutHandler() {
                    @Override
                    public void logout(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, Authentication authentication) {
                        HttpSession session = httpServletRequest.getSession();
                        session.invalidate();
                    }
                })
                .logoutSuccessHandler(new LogoutSuccessHandler() {
                    @Override
                    public void onLogoutSuccess(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, Authentication authentication) throws IOException, ServletException {
                        httpServletResponse.sendRedirect("/login");
                    }
                })
                .deleteCookies("remember-me") // cookie name

        /**
         *      로그인시 이전 정보를 기억하여 로그인
         * */
        .and()
                .rememberMe()
                .rememberMeParameter("remember") /** 기본 파라미터명 : remember-me, 생성할 remember 쿠키명과 일치해야한다. **/
                .tokenValiditySeconds(3600) /** Default = 14일 **/
                //.alwaysRemember(true) /** remember me 기능이 비활성화 상태여도 항상 실행 **/
                .userDetailsService(userDetailsService); /** 사용자 계정을 처리할 때 필요한 메소드 **/

        /**     세션 관리, 동시적 세션 제어
         * */
        http.sessionManagement()
                .maximumSessions(1) /** 최대 허용 가능 세션 수, -1 : 무제한 로그인 세션 허용 **/
                .maxSessionsPreventsLogin(false);  /** 동시 로그인 차단, default = false (기존 세션 만료) **/
                //.invalidSessionUrl("/invalid") /** 세션이 유효하지 않은 경우 이동할 페이지 **/
                //.expiredUrl("/expired"); /** 세션이 만료된 경우 이동할 페이지 **/

        /**     세션 고정 보호
         *      : changeSessionId(default), none, migrateSession, newSession
         * */
        http.sessionManagement()
                .sessionFixation().changeSessionId();

        /**     세션 정책
         *      Always : 스프링 시큐리티가 항상 세션 생성
         *      If_Required : 스프링 시큐리티가 필요 시 생성(default)
         *      Never : 스프링 시큐리티가 생성하지 않지만 이미 존재하면 사용
         *      Stateless : 스프링 시큐리티가 생성하지 않고 존재해도 사용하지 않음
         * */
        http.sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED);

        /**     부모 - 자식 Thread 간 authentication 공유
         * */
        SecurityContextHolder.setStrategyName(SecurityContextHolder.MODE_INHERITABLETHREADLOCAL);

    }
}

@Configuration
@Order(1)
class SecurityConfig2 extends WebSecurityConfigurerAdapter{
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
                .anyRequest().permitAll()
                .and()
                .formLogin();
    }
}


















