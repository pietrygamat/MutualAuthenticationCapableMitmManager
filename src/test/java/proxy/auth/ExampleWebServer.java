package proxy.auth;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;

/**
 * Webserver configured to require client authentication
 * See application.properties to disable this behavior
 */
@Controller
@SpringBootApplication
public class ExampleWebServer {
    public static void main(String... args) {
        SpringApplication.run(ExampleWebServer.class);
    }

    @ResponseBody
    @RequestMapping("/")
    public String testPage() {
        return "<h1 id='header'>Hello</h1>";
    }
}
