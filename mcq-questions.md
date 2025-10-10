# MCQ Questions - API Security Hardening

## Instructions
Choose the best answer for each question. Each question has only one correct answer.

---

### Question 1: SQL Injection
What is SQL injection?

A) A method to optimize database queries  
B) An attack where malicious SQL code is inserted into input fields to manipulate database queries  
C) A way to backup databases  
D) A database connection method  

**Answer: B**

---

### Question 2: Rate Limiting
What is the primary purpose of rate limiting in APIs?

A) To make APIs faster  
B) To reduce server costs  
C) To prevent API abuse by limiting the number of requests from a client within a time window  
D) To improve code quality  

**Answer: C**

---

### Question 3: XSS Attack
What does XSS stand for and what is it?

A) XML Security System - a security protocol  
B) Cross-Site Scripting - an attack that injects malicious scripts into web pages  
C) eXtended Security Standard - a security framework  
D) eXternal Style Sheets - a CSS feature  

**Answer: B**

---

### Question 4: Security Headers
Which HTTP header prevents a page from being displayed in an iframe to protect against clickjacking?

A) X-Content-Type-Options  
B) X-XSS-Protection  
C) X-Frame-Options  
D) Content-Security-Policy  

**Answer: C**

---

### Question 5: Brute Force Attack
What is a brute force attack on a login system?

A) A server crash  
B) Systematically trying many password combinations to gain unauthorized access  
C) A network configuration error  
D) A database optimization technique  

**Answer: B**

---

### Question 6: HTTPS
Why is HTTPS important for API security?

A) It makes APIs faster  
B) It encrypts data in transit, preventing eavesdropping and man-in-the-middle attacks  
C) It reduces server load  
D) It's only needed for websites, not APIs  

**Answer: B**

---

### Question 7: Input Validation
Why is input validation critical for API security?

A) To improve performance  
B) To prevent injection attacks and ensure data integrity by validating and sanitizing user input  
C) To reduce code size  
D) To make debugging easier  

**Answer: B**

---

### Question 8: Content-Security-Policy
What does the Content-Security-Policy (CSP) header do?

A) Encrypts content  
B) Controls which resources can be loaded and executed, helping prevent XSS attacks  
C) Compresses content  
D) Caches content  

**Answer: B**

---

### Question 9: Account Lockout
What is the purpose of account lockout after failed login attempts?

A) To save server resources  
B) To prevent brute force attacks by temporarily blocking access after multiple failed attempts  
C) To improve login speed  
D) To delete inactive accounts  

**Answer: B**

---

### Question 10: API Key Authentication
What is an API key used for?

A) To encrypt data  
B) To authenticate and authorize API requests  
C) To improve performance  
D) To compress requests  

**Answer: B**

---

### Question 11: Parameterized Queries
How do parameterized queries prevent SQL injection?

A) They make queries faster  
B) They separate SQL code from data, preventing malicious SQL from being executed  
C) They encrypt the database  
D) They reduce database size  

**Answer: B**

---

### Question 12: CORS
What does CORS (Cross-Origin Resource Sharing) control?

A) Database connections  
B) Which domains can access your API resources  
C) Server performance  
D) File uploads  

**Answer: B**

---

### Question 13: Rate Limit Response
What HTTP status code should be returned when a rate limit is exceeded?

A) 200 OK  
B) 404 Not Found  
C) 500 Internal Server Error  
D) 429 Too Many Requests  

**Answer: D**

---

### Question 14: Defense in Depth
What does "defense in depth" mean in security?

A) Using only one strong security measure  
B) Implementing multiple layers of security so if one fails, others still protect  
C) Making security very complex  
D) Focusing only on network security  

**Answer: B**

---

### Question 15: OWASP Top 10
What is the OWASP Top 10?

A) A list of the top 10 programming languages  
B) A list of the most critical web application security risks  
C) A list of the top 10 web frameworks  
D) A list of the top 10 databases  

**Answer: B**

---

## Answer Key Summary

1. B - SQL injection manipulates database queries  
2. C - Rate limiting prevents API abuse  
3. B - XSS injects malicious scripts  
4. C - X-Frame-Options prevents clickjacking  
5. B - Brute force tries many passwords  
6. B - HTTPS encrypts data in transit  
7. B - Input validation prevents injection attacks  
8. B - CSP controls resource loading  
9. B - Account lockout prevents brute force  
10. B - API key authenticates requests  
11. B - Parameterized queries separate code from data  
12. B - CORS controls domain access  
13. D - 429 for rate limit exceeded  
14. B - Multiple security layers  
15. B - OWASP Top 10 lists critical risks  

---

**Total Questions: 15**  
**Topics Covered:** SQL injection, XSS, Rate limiting, Brute force attacks, Security headers, Input validation, HTTPS, API authentication, CORS, Defense in depth, OWASP Top 10

**Difficulty Level:** Beginner to Intermediate  
**Passing Score:** 80% (12/15 correct answers)
