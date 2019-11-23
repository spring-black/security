package springblack.security;

import io.jsonwebtoken.Jwts;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static java.util.Collections.emptyList;

public class TokenAuthenticationService {

    static final String TOKEN_PREFIX  = "Bearer";
    static final String HEADER_STRING = "Authorization";

    static void addAuthentication(HttpServletResponse res, String username) {

//        String jwt = UserLogin.getJWT(username, UserLogin.ONE_DAY_MILLIS);
//
//        res.addHeader(HEADER_STRING, TOKEN_PREFIX + " " + jwt);
//
//        try {
//
//            res.setContentType("application/json");
//
//            PrintWriter out = res.getWriter();
//
//            out.println("{");
//            out.println("\"jwt\":" + "\"" + jwt + "\"");
//            out.println("}");
//
//            out.close();
//
//        } catch (IOException e) {
//
//            e.printStackTrace();
//
//        }

    }

    static Authentication getAuthentication(HttpServletRequest request) {

        String token = request.getHeader(HEADER_STRING);

        if (token != null) {

            String user = Jwts.parser().setSigningKey(System.getenv("JWT_SECRET")).parseClaimsJws(token.replace(TOKEN_PREFIX, "")).getBody().getSubject();

            return user != null ? new UsernamePasswordAuthenticationToken(user, null, emptyList()) : null;

        }

        return null;

    }

}
