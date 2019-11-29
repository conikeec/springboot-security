Spring Boot Security
====================

The application showcases use of Spring Boot with key features/options of Spring Security enabled, such as:

* Login form (implementing recommended Authorization and Authentication)
* HTTPS Transport Security
* CSRF protecton
* Session Fixation Protection
* Security Header Configuration (ClickJacking)
* XSS protection
* Secrets Management (TBD)
* Domain Access Objects-based authentication
* Basic "remember me" authentication
* URL-based security
* Method-level security

Quick start
-----------
1. Build Package : `mvn clean compile package`
2. To run : `mvn clean spring-boot:run`
3. Point your browser to [http://localhost:8080/](http://localhost:8080/)

Screen shot
-----------
Index Page

[http://localhost:8080/](http://localhost:8080/)

Login Page

[http://localhost:8080/login](http://localhost:8080/login)

Menu Page (Post Auth)

[http://localhost:8080/](http://localhost:8080/)

List Users Page

[http://localhost:8080/users](http://localhost:8080/users)

Create New User Page

[http://localhost:8080/user/create](http://localhost:8080/user/create)

List Users Page

[http://localhost:8080/users](http://localhost:8080/users)

User Details Page

[http://localhost:8080/user/1](http://localhost:8080/user/1)