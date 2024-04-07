package com.smartlab.apigateway.filter;

import com.smartlab.apigateway.util.JwtUtil;
import lombok.Data;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;

import java.util.List;


@Component
public class ClienteFilter extends AbstractGatewayFilterFactory<ClienteFilter.Config> {
    @Autowired
    private RouteValidator validator;

    @Autowired
    private JwtUtil jwtUtil;

    public ClienteFilter(){
        super(Config.class);
    }

    @Override
    public GatewayFilter apply(Config config) {
        return ((exchange, chain) -> {
            ServerHttpRequest request = null;
            if (validator.isSecured.test(exchange.getRequest())) {
                //header contains token or not
                if (!exchange.getRequest().getHeaders().containsKey(HttpHeaders.AUTHORIZATION)) {
                    throw new RuntimeException("missing authorization header");
                }

                String authHeader = exchange.getRequest().getHeaders().get(HttpHeaders.AUTHORIZATION).get(0);
                if (authHeader != null && authHeader.startsWith("Bearer ")) {
                    authHeader = authHeader.substring(7);
                }
                try {
                    jwtUtil.validateToken(authHeader);

                    List<String> roles = jwtUtil.extractRoles(authHeader);
                    System.out.println(roles);
                    System.out.println(config.getRol());
                    if(roles.contains(config.getRol())){
                        request = exchange.getRequest()
                                .mutate()
                                .header("LoggedInUser", jwtUtil.extractUserName(authHeader))
                                .build();
                    } else {
                        throw new RuntimeException("Unauthorized access to application");
                    }


                } catch (Exception e) {
                    System.out.println("invalid access...!");
                    throw new RuntimeException("un authorized access to application");
                }
            }
            return chain.filter(exchange.mutate().request(request).build());
        });
    }
    @Data
    public static class Config{
        private String rol;
    }
}
