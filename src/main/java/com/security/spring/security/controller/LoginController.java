package com.security.spring.security.controller;

import com.security.spring.security.services.JWTService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;
import java.util.Map;

@RestController
public class LoginController {

    @Autowired
    private JWTService jwtService;

/*    public LoginController(JWTService jwtService) {
        this.jwtService = jwtService;
    }*/

    @PostMapping("/login")
    public String getToken(Authentication authentication) {
        return jwtService.generateToken(authentication);
    }

    /*  @Autowired
    private OAuth2AuthorizedClientService authorizedClientService;

    @GetMapping("/user")
    public String getUser(){
        return "welcome user";
    }

    @GetMapping("/admin")
    public String getAdmin(){
        return "welcome admin";
    }

    @GetMapping("/")
    public String getUserInfo(Principal user, @AuthenticationPrincipal OidcUser oicdUser){
        StringBuilder userInfo = new StringBuilder();
        if(user instanceof UsernamePasswordAuthenticationToken){
            userInfo.append(getUsernamePasswordLoginInfo(user));
        } else if (user instanceof OAuth2AuthenticationToken) {
            // token d'acces à l'avantage de ressources
            userInfo.append(getOAuth2LoginInfo(user, oicdUser));
        }
        return userInfo.toString();
    }

    private StringBuffer getUsernamePasswordLoginInfo(Principal user) {
        StringBuffer usernameInfo = new StringBuffer();

        UsernamePasswordAuthenticationToken token = (UsernamePasswordAuthenticationToken) user;

        if (token.isAuthenticated()){
            User userDetail =(User) token.getPrincipal();

            usernameInfo.append("Welcome ").append(userDetail.getUsername());
        } else {
            usernameInfo.append("NA");
        }
        return usernameInfo;
    }



    private StringBuffer getOAuth2LoginInfo(Principal user, OidcUser oicdUser){
        StringBuffer protectedInfo = new StringBuffer();
        OAuth2AuthenticationToken authToken = ((OAuth2AuthenticationToken) user);

        OAuth2AuthorizedClient authClient = this.authorizedClientService.loadAuthorizedClient(authToken.getAuthorizedClientRegistrationId(), authToken.getName());

        if(authToken.isAuthenticated()){
            String userToken = authClient.getAccessToken().getTokenValue();
            Map<String,Object> userAttributes =((DefaultOAuth2User) authToken.getPrincipal()).getAttributes();

            protectedInfo.append("Welcome, " + userAttributes.get("name")+"<br><br>");
            protectedInfo.append("e-mail: " + userAttributes.get("email")+"<br><br>");
            protectedInfo.append("Access Token: " + userToken+"<br><br>");

            OidcIdToken idToken = oicdUser.getIdToken();

            if (idToken != null) {
                protectedInfo.append("idToken value : " + idToken.getTokenValue());
                protectedInfo.append("token mapped value <br> ");

                Map<String, Object> claims = idToken.getClaims();
                for(String key : claims.keySet()){
                    protectedInfo.append(" "+key+ ": " + claims.get(key)+ "<br>");
                }

                protectedInfo.append("idToken value : " + idToken.getTokenValue());
            }

        }
        else{
            protectedInfo.append("NA");
        }
        return protectedInfo;
    }*/

}
