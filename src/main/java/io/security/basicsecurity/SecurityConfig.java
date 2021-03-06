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

    /**     SecurityConfig : ????????? ?????? ?????? ?????? ?????????
     *      WebSecurityConfigurerAdapter : ????????? ??????????????? ??? ?????? ?????? ????????? ??? ??????
     *      HttpSecurity : ???????????? ?????? ????????? ????????? ??? ?????? API ??????
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

        http    /** ???????????? ????????? ?????? ?????? ??????.  **/
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
         *      ?????? formLogin?????? ???????????? url??????
         *      ?????? html form??? action, href?????? url??? ???????????? ??????.
         * */

        http
                .formLogin()
                .successHandler(new AuthenticationSuccessHandler() { /** ????????? ????????? ????????? ????????? ???????????? ?????? **/
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
         *      ???????????? ?????? ????????? ???????????? ?????????
         * */
        .and()
                .rememberMe()
                .rememberMeParameter("remember") /** ?????? ??????????????? : remember-me, ????????? remember ???????????? ??????????????????. **/
                .tokenValiditySeconds(3600) /** Default = 14??? **/
                //.alwaysRemember(true) /** remember me ????????? ???????????? ???????????? ?????? ?????? **/
                .userDetailsService(userDetailsService); /** ????????? ????????? ????????? ??? ????????? ????????? **/

        /**     ?????? ??????, ????????? ?????? ??????
         * */
        http.sessionManagement()
                .maximumSessions(1) /** ?????? ?????? ?????? ?????? ???, -1 : ????????? ????????? ?????? ?????? **/
                .maxSessionsPreventsLogin(false);  /** ?????? ????????? ??????, default = false (?????? ?????? ??????) **/
                //.invalidSessionUrl("/invalid") /** ????????? ???????????? ?????? ?????? ????????? ????????? **/
                //.expiredUrl("/expired"); /** ????????? ????????? ?????? ????????? ????????? **/

        /**     ?????? ?????? ??????
         *      : changeSessionId(default), none, migrateSession, newSession
         * */
        http.sessionManagement()
                .sessionFixation().changeSessionId();

        /**     ?????? ??????
         *      Always : ????????? ??????????????? ?????? ?????? ??????
         *      If_Required : ????????? ??????????????? ?????? ??? ??????(default)
         *      Never : ????????? ??????????????? ???????????? ????????? ?????? ???????????? ??????
         *      Stateless : ????????? ??????????????? ???????????? ?????? ???????????? ???????????? ??????
         * */
        http.sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED);

        /**     ?????? - ?????? Thread ??? authentication ??????
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


















