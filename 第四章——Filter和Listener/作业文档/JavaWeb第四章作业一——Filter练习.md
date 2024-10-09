# JavaWeb第四章作业一——Filter练习

**学院：省级示范性软件学院**

**题目：**《JavaWeb第四章作业一——Filter练习》

**姓名：**陈冰琰

**学号：**2000770164

**班级：**软工2202

**日期：**2024-10-09

**环境：**windows11 IDEA24.1 jdk1.8 tomcat9.0.27 

## 文档：

为了实现filter登录拦截，先要规划整体结构

1·先做Servlet部分 设计RegisterServlet LoginServlet SessionDeleteServlet（项目文件里叫SessionDelete）

RegisterServlet：用HashMap存储客户端注册时输入的username和password，注册完成后重定向到LoginServlet登录，并用一个isValid方法判断登陆时输入的username和password是否时HaspMap中储存的值。真正的项目开发应该用数据库来做。

LoginServlet：如果isValid为真，重定向到主页（登录成功页面）；失败则重定向到登录失败页面

SessionDelete：删除Session，重定向到登陆页面（login.jsp）

2·前端部分实现

index.jsp 公共页面，默认页面

register.jsp 注册页面

login.jsp 登录页面

success.jsp 主页，登录成功页面

error.jsp 登录失败页面

3·Filter部分

设置排除路径列表

```java
private static final List<String> allowPaths = Arrays.asList("/login.jsp", "/register.jsp", "/index.jsp","/login","/register","/error.jsp");
```

常规init() destroy()方法

注意：要用当前请求的uri路径减去上下文路径才能匹配上面的排除路径

```java
//获取uri
        String uri = req.getRequestURI();
        //获取上下文路径
        String contextPath = req.getContextPath();
        // 去除上下文路径，保留相对路径
        String path = uri.substring(contextPath.length());
```

剩余就是条件判断

```java
if(allowPaths.contains(path)){
            filterChain.doFilter(servletRequest, servletResponse);
}
```

放行排除路径

```java
else if (session != null && session.getAttribute("username") != null && session.getAttribute("password") != null) {
            filterChain.doFilter(servletRequest, servletResponse);
        }
```

session不为空且username及密码属性不为空，则放行（LoginServlet里，用户名与密码匹配HashMap后就添加了当前username和password作为session属性。（但是password作为session属性好像不安全哈，懒得改了:)））

```java
 else {
            resp.sendRedirect(req.getContextPath() + "/login.jsp");
        }
```

不符合上述条件的均重定向到登陆页面

