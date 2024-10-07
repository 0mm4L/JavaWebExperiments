# JavaWeb第四章 会话技术——扩展作业

**学院：省级示范性软件学院**

**题目：**会话技术扩展作业

**姓名：**陈冰琰

**学号：**2000770164

**班级：**软工2202

**日期：**2024-09-27

**备注：**本次作业内容全部来自csdn，github，chatgpt，本人所写内容仅代表本人已学习阅读，不代表完全理解和掌握。

## 1·**会话安全性**

### 1·会话劫持和防御

在 Java Web 开发中，会话安全性是确保用户身份和数据不被未经授权的第三方窃取和滥用的重要环节。会话劫持是攻击者通过**窃取合法用户的会话ID**来冒充该用户，进行恶意操作的攻击行为。

#### 会话劫持的部分手段：

**网络嗅探**：攻击者通过**监听网络流量**，窃取会话ID。

**跨站脚本攻击（XSS）**：通过向用户页面**注入恶意脚本**，盗取用户的会话ID。

**会话固定攻击（Session Fixation）**：攻击者向受害者**提供一个已知的会话ID**，并诱导受害者在该会话中进行操作。

#### 防御会话劫持的策略：

##### 1·使用https

 HTTPS 协议加密会话ID，在web.xml中配置https

```xml
<security-constraint>
    <web-resource-collection>
        <web-resource-name>Protected Area</web-resource-name>
        <url-pattern>/*</url-pattern>
    </web-resource-collection>
    <user-data-constraint>
        <transport-guarantee>CONFIDENTIAL</transport-guarantee>
    </user-data-constraint>
</security-constraint>

```

##### 2·设置 HttpOnly 和 Secure Cookie 标志

HttpOnly 标志可以防止通过 JavaScript 访问会话 Cookie。

Secure 标志确保 Cookie 只能通过 HTTPS 发送。

```java
Cookie sessionCookie = new Cookie("JSESSIONID", session.getId());
sessionCookie.setHttpOnly(true);  
sessionCookie.setSecure(true);   
response.addCookie(sessionCookie);

```

##### 3·定期更换会话ID

在用户登录或执行关键操作后，生成一个新的会话ID

```java
HttpSession oldSession = request.getSession(false);
if (oldSession != null) {
    oldSession.invalidate();  
}
HttpSession newSession = request.getSession(true);  

```

##### 4·使用 IP 地址和 User-Agent 验证

```java
String currentIp = request.getRemoteAddr();
String currentUserAgent = request.getHeader("User-Agent");

String sessionIp = (String) session.getAttribute("userIp");
String sessionUserAgent = (String) session.getAttribute("userAgent");

if (!currentIp.equals(sessionIp) || !currentUserAgent.equals(sessionUserAgent)) {
    session.invalidate();  
}

```

##### 5·防范 XSS 攻击

```
<c:out value="${userInput}" />
```

### 2·跨站脚本攻击（XSS）和防御

XSS是Web安全中常见的攻击之一，攻击者通过注入恶意脚本到网页中，诱导用户执行这些脚本，从而窃取用户数据、劫持会话或执行其他恶意操作。XSS 攻击的核心是**未对用户输入的数据进行有效的过滤或转义，导致恶意脚本被浏览器执行。**

#### **1·XSS 的类型**

##### （1）**存储型（Stored XSS）**

存储型XSS攻击发生在恶意脚本被存储在服务器端，并在后续用户访问页面时执行。常见场景是用户提交含有恶意脚本的评论、论坛帖子等，其他用户访问该页面时，脚本会在浏览器中执行。

##### （2）**反射型（Reflected XSS）**

反射型XSS攻击发生在服务器立即将恶意脚本反射回用户的请求中。例如，攻击者通过带有恶意代码的URL诱导用户点击，服务器将该代码包含在响应中，浏览器会执行该代码。

##### （3）**DOM型（DOM-based XSS）**

DOM型XSS攻击发生在客户端（浏览器端）的JavaScript代码中。恶意脚本通过修改页面的DOM结构被执行，而不需要经过服务器端的响应。

#### 2·XSS 攻击防御策略

##### （1）**输出转义（Output Encoding）**

最基本的防御方式是对用户输入的数据进行适当的输出转义，避免数据被解释为代码。不同的输出环境需要不同的转义策略，比如HTML、JavaScript、URL等。

使用 JSTL 的 `<c:out>` 标签来转义输出，防止HTML和JavaScript代码注入。

```jsp
<% String userInput = request.getParameter("userInput"); %>
<c:out value="${userInput}" />

```

自定义编码函数来手动转义

```java
public String escapeHtml(String input) {
    if (input == null) {
        return null;
    }
    return input.replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace("\"", "&quot;")
                .replace("'", "&#x27;");
}
```

##### （2）**验证用户输入（Input Validation）**

尽量限制用户输入的格式和内容，防止恶意代码通过合法输入渠道进入系统。对于文本输入，可以使用白名单或正则表达式进行验证。

允许输入的内容和仅包含字母和汉字

```java
public boolean isValidInput(String input) {
    return input != null && input.matches("^[a-zA-Z0-9]*$");
}

```

##### （3）**内容安全策略（CSP, Content Security Policy）**

内容安全策略是通过设置响应头来指定浏览器应该执行哪些资源，从而防止注入脚本执行。CSP 可以有效防御 XSS 攻击，特别是结合其他防御措施时。

 设置 CSP 响应头，限制仅允许同源脚本执行

```java
response.setHeader("Content-Security-Policy", "script-src 'self'");
```

##### （4）**HTTP Only 和 Secure Cookie**

上文已提到

##### （5）**避免在HTML中直接使用用户输入的数据**

避免直接将用户输入的数据放入HTML、JavaScript、CSS等位置，特别是 `<script>`、`<style>`、`<img>` 等标签的属性中。如果需要使用用户输入的数据，必须进行严格的转义和验证。

```jsp
<% String name = request.getParameter("name"); %>
<h1>Welcome, <%= name %></h1>
```

避免上述代码并改为

```jsp
<c:out value="${param.name}" />
```

##### （6）**使用安全框架**

使用诸如 OWASP 的 ESAPI (Enterprise Security API) 等安全框架，帮助开发者防止 XSS 攻击。ESAPI 提供了各种编码和验证函数，可以简化防御工作。

```java
import org.owasp.esapi.ESAPI;
import org.owasp.esapi.errors.EncodingException;

public String safeOutput(String input) {
    try {
        return ESAPI.encoder().encodeForHTML(input);
    } catch (EncodingException e) {
        return "";
    }
}

```

### 3·跨站请求伪造（CSRF）和防御

跨站请求伪造中，攻击者通过伪造用户的请求，诱使用户在不知情的情况下执行未授权的操作。而这些操作往往通过cookie和session实现

#### 1. **CSRF 攻击的原理**

CSRF攻击的基本过程：

1. 用户登录受信任的站点A，并获得了会话信息（如会话Cookie）。
2. 攻击者诱导用户访问另一个恶意站点B，站点B包含向站点A发起的恶意请求。
3. 浏览器自动携带站点A的Cookie，站点A在不验证请求的合法性的情况下，执行了攻击者发起的操作。

#### 2.**防御 CSRF 的策略**

**CSRF Token（推荐方法）**

CSRF Token 是目前最常用且最有效的防御策略。每个敏感操作的请求都会携带一个随机生成的令牌（Token），服务器验证令牌是否匹配，从而确认请求的合法性。

生成并附加 CSRF Token 到表单

```java
String csrfToken = UUID.randomUUID().toString();
session.setAttribute("csrfToken", csrfToken);

out.println("<form action='/transfer' method='POST'>");
out.println("<input type='hidden' name='csrfToken' value='" + csrfToken + "' />");
out.println("<input type='text' name='amount' />");
out.println("<input type='submit' value='Transfer' />");
out.println("</form>");

```

服务器端验证 CSRF Token

```
String requestCsrfToken = request.getParameter("csrfToken");

String sessionCsrfToken = (String) session.getAttribute("csrfToken");

if (sessionCsrfToken == null || !sessionCsrfToken.equals(requestCsrfToken)) {
    throw new SecurityException("CSRF token validation failed.");
}
```

## 2·**分布式会话管理**

### 1. **分布式环境下的会话同步问题**

分布式环境中，多个服务器处理不同的用户请求。传统情况下，会话（Session）存储在某个服务器的内存中，但在分布式架构中，用户的请求可能被不同的服务器处理。这样会导致会话信息无法在不同服务器之间共享，造成用户登录信息丢失等问题。

### 2.**Session 集群解决方案**

#### （1）**Session 复制**

每个服务器都存储相同的会话数据。当一台服务器更新了会话数据时，所有其他服务器都会同步这些数据。

#### （2）**Session 绑定（Sticky Session）**

用户的请求总是被路由到同一台服务器处理，这样会话信息只保存在一台服务器上。

#### （3）**集中式 Session 存储**

将会话存储在一个集中式的存储系统中（例如数据库、Redis等），所有服务器从同一个地方读取和写入会话数据。

### 3.**使用 Redis 实现分布式会话**

假设你在使用 Spring Boot，可以使用 `spring-session-data-redis` 来实现分布式会话存储。

添加依赖：

```xml
<dependency>
    <groupId>org.springframework.session</groupId>
    <artifactId>spring-session-data-redis</artifactId>
</dependency>

```

配置 application.properties：

```properties
spring.redis.host=localhost
spring.redis.port=6379

spring.session.store-type=redis

```

启动 Redis

## 3·**会话状态的序列化和反序列化**

### 1. **会话状态的序列化和反序列化**

会话状态需要在多个服务器之间共享。这意味着会话数据可能需要存储在外部系统中，而这些系统通常不能直接存储 Java 对象。因此，我们需要将 Java 对象转换为可存储的格式，这个过程称为**序列化**。从外部存储系统取出数据时，再将其转换回 Java 对象的过程称为**反序列化**。

### 2·**为什么需要序列化会话状态**

在分布式系统中，会话状态通常存储在集中式的缓存或数据库中，序列化有以下几个原因：

- **跨系统存储**：Redis、数据库等外部存储系统无法直接处理 Java 对象，需要序列化为二进制格式或其他可传输的格式。
- **持久化**：某些场景下，需要持久化会话状态到磁盘或数据库中以便恢复。
- **高可用性**：通过序列化，可以将会话状态转移到其他服务器，保证用户请求的连续性。

### 3.**Java 对象的序列化**

Java 提供了默认的序列化机制，可以将其对象序列化为字节流。序列化后的对象可以写入文件、传输到网络或存储到Redis等外部系统。

**实现 Serializable 接口**：

```java
import java.io.Serializable;

public class UserSession implements Serializable {
    private static final long serialVersionUID = 1L;
    
    private String username;
    private String role;
    
    public UserSession(String username, String role) {
        this.username = username;
        this.role = role;
    }

}

```

**序列化对象**：

```java
import java.io.FileOutputStream;
import java.io.ObjectOutputStream;

public class SerializeExample {
    public static void main(String[] args) {
        UserSession session = new UserSession("user1", "admin");

        try (FileOutputStream fileOut = new FileOutputStream("session.ser");
             ObjectOutputStream out = new ObjectOutputStream(fileOut)) {
            out.writeObject(session);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
```

**反序列化对象**：

```java
import java.io.FileInputStream;
import java.io.ObjectInputStream;

public class DeserializeExample {
    public static void main(String[] args) {
        UserSession session = null;

        try (FileInputStream fileIn = new FileInputStream("session.ser");
             ObjectInputStream in = new ObjectInputStream(fileIn)) {
            session = (UserSession) in.readObject();
        } catch (Exception e) {
            e.printStackTrace();
        }

        System.out.println("Username: " + session.getUsername());
        System.out.println("Role: " + session.getRole());
    }
}

```

### 4.**自定义序列化策略**

有时默认的序列化方式并不适合所有场景。比如，如果某些字段不需要序列化（如密码字段），或者想自定义对象序列化的方式，可以通过实现 writeObject 和 readObject 方法来自定义序列化。

自动序列化：

```java
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;

public class SecureSession implements Serializable {
    private static final long serialVersionUID = 1L;

    private String username;
    private transient String password; 

    public SecureSession(String username, String password) {
        this.username = username;
        this.password = password;
    }

        private void writeObject(ObjectOutputStream out) throws IOException {
        out.defaultWriteObject();
        out.writeObject("hashed_" + password); 
    }

    private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
        in.defaultReadObject();
        String hashedPassword = (String) in.readObject();
        this.password = hashedPassword.replace("hashed_", "");
    }

    public String getUsername() {
        return username;
    }

    public String getPassword() {
        return password;
    }
}

```

