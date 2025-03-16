Запуск проекта:
docker-compose up -d --build

1. открыть http://localhost:3000/
2. залогиниться под юзером с realmRole= "prothetic_user", например prothetic1/prothetic123
3. нажать download report (в консоле F12 будет виден токен и ответ API)

Ручная проверка:

1. получить токен:

curl -X POST   http://localhost:8080/realms/reports-realm/protocol/openid-connect/token   -H "Content-Type: application/x-www-form-urlencoded"   -d "client_id=reports-frontend"   -d "username=prothetic1"   -d "password=prothetic123"   -d "grant_type=password"


2. запрос с токеном:
curl -X GET \
  http://localhost:8000/reports \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJtZUZiUHo1TU9mYW5pUGpFVVVUdUZ3UDlVcEUxVlFhNXhWdTBqRlRRNE53In0.eyJleHAiOjE3NDIwNDc2ODQsImlhdCI6MTc0MjA0NzM4NCwianRpIjoiMDE5M2EzYjgtNWY3OC00NDM4LWFjOGEtZDU3M2Q1YjIzZmQxIiwiaXNzIjoiaHR0cDovL2xvY2FsaG9zdDo4MDgwL3JlYWxtcy9yZXBvcnRzLXJlYWxtIiwic3ViIjoiOTBjOTFkZjMtODU5NS00ZWUzLWIxNzktOThiZDJhMDhiYTk2IiwidHlwIjoiQmVhcmVyIiwiYXpwIjoicmVwb3J0cy1mcm9udGVuZCIsInNlc3Npb25fc3RhdGUiOiI2MTVmY2NkMy0wOWFkLTRiZjYtODg1Ny01ZjUyMTZkZjVhNmYiLCJhY3IiOiIxIiwiYWxsb3dlZC1vcmlnaW5zIjpbImh0dHA6Ly9sb2NhbGhvc3Q6MzAwMCJdLCJyZWFsbV9hY2Nlc3MiOnsicm9sZXMiOlsicHJvdGhldGljX3VzZXIiXX0sInNjb3BlIjoicHJvZmlsZSBlbWFpbCIsInNpZCI6IjYxNWZjY2QzLTA5YWQtNGJmNi04ODU3LTVmNTIxNmRmNWE2ZiIsImVtYWlsX3ZlcmlmaWVkIjp0cnVlLCJuYW1lIjoiUHJvdGhldGljIE9uZSIsInByZWZlcnJlZF91c2VybmFtZSI6InByb3RoZXRpYzEiLCJnaXZlbl9uYW1lIjoiUHJvdGhldGljIiwiZmFtaWx5X25hbWUiOiJPbmUiLCJlbWFpbCI6InByb3RoZXRpYzFAZXhhbXBsZS5jb20ifQ.LPXbCpmD9zgvz-2a9p-k5PPIatzARRanRvUz0E08GOsYalWCuUOdGXmB5DqcX7ygKq8zUfMJ6LLOORDXCcli1ncTT8gEqJnu0NQOezF3TGwSrQMP8dNOaZh9rzr_Sc74uISCFngdqIeKEEHVlTI_qFgzZvC7hXLe5zSWSAD0A3FM8ZPTgXNUhEBquDK4_8B9RDyY95DIDbJobwAQxVLI-0ZAoF2hJRtmNFC8yQLnLM_GmrCPLrppOZIP9qyD7ZE9zzC1yHAxap8P2yBLo24oZt87Js0WNL0PtibZllimYsk-idqHBZdB7K9N46cjsv-r5uKaLyZvN-Xlw-AaVlU47Q" \
  -H "Content-Type: application/json"

3. проверяем логи

docker-compose logs api

api-1  | 2025-03-15T17:41:09.587Z DEBUG 1 --- [nio-8000-exec-2] o.s.web.client.RestTemplate              : HTTP GET http://keycloak:8080/realms/reports-realm/protocol/openid-connect/certs
api-1  | 2025-03-15T17:41:09.592Z DEBUG 1 --- [nio-8000-exec-2] o.s.web.client.RestTemplate              : Accept=[text/plain, application/json, application/*+json, */*]
api-1  | 2025-03-15T17:41:09.619Z DEBUG 1 --- [nio-8000-exec-2] o.s.web.client.RestTemplate              : Response 200 OK
api-1  | 2025-03-15T17:41:09.620Z DEBUG 1 --- [nio-8000-exec-2] o.s.web.client.RestTemplate              : Reading to [java.lang.String] as "application/json"
api-1  | 2025-03-15T17:41:09.636Z  INFO 1 --- [nio-8000-exec-2] r.y.reports_api.config.SecurityConfig    : Validating JWT claims: {"sub":"90c91df3-8595-4ee3-b179-98bd2a08ba96","email_verified":true,"allowed-origins"
:["http://localhost:3000"],"iss":"http://localhost:8080/realms/reports-realm","typ":"Bearer","preferred_username":"prothetic1","given_name":"Prothetic","nonce":"3369637a-2bf6-44e7-a460-c74fc36e9804","sid":"d41d7456-
59ca-419d-b472-e960eb5cbf7b","acr":"1","realm_access":{"roles":["prothetic_user"]},"azp":"reports-frontend","auth_time":1742060467,"scope":"openid profile email","name":"Prothetic One","exp":1742060768,"session_stat
e":"d41d7456-59ca-419d-b472-e960eb5cbf7b","iat":1742060468,"family_name":"One","jti":"e4ed9724-9162-4eef-8f20-4a601f53594a","email":"prothetic1@example.com"}
api-1  | 2025-03-15T17:41:09.640Z DEBUG 1 --- [nio-8000-exec-2] o.s.s.o.s.r.a.JwtAuthenticationProvider  : Authenticated token
api-1  | 2025-03-15T17:41:09.640Z DEBUG 1 --- [nio-8000-exec-2] .s.r.w.a.BearerTokenAuthenticationFilter : Set SecurityContextHolder to JwtAuthenticationToken [Principal=org.springframework.security.oauth2.jwt.Jwt@5
22bbac8, Credentials=[PROTECTED], Authenticated=true, Details=WebAuthenticationDetails [RemoteIpAddress=172.18.0.1, SessionId=null], Granted Authorities=[ROLE_PROTHETIC_USER]]
api-1  | 2025-03-15T17:41:09.640Z  INFO 1 --- [nio-8000-exec-2] r.y.reports_api.config.SecurityConfig    : User roles: [ROLE_PROTHETIC_USER]
api-1  | 2025-03-15T17:41:09.642Z DEBUG 1 --- [nio-8000-exec-2] o.s.security.web.FilterChainProxy        : Secured GET /reports
api-1  | 2025-03-15T17:41:09.643Z DEBUG 1 --- [nio-8000-exec-2] o.s.web.servlet.DispatcherServlet        : GET "/reports", parameters={}
api-1  | 2025-03-15T17:41:09.644Z DEBUG 1 --- [nio-8000-exec-2] s.w.s.m.m.a.RequestMappingHandlerMapping : Mapped to ru.yandex_practicum.reports_api.controller.ReportController#getReports()
api-1  | 2025-03-15T17:41:09.664Z DEBUG 1 --- [nio-8000-exec-2] m.m.a.RequestResponseBodyMethodProcessor : Using 'application/json', given [*/*] and supported [application/json, application/*+json]
api-1  | 2025-03-15T17:41:09.665Z DEBUG 1 --- [nio-8000-exec-2] m.m.a.RequestResponseBodyMethodProcessor : Writing [{message=big big report, trust me!}]
api-1  | 2025-03-15T17:41:09.673Z DEBUG 1 --- [nio-8000-exec-2] o.s.web.servlet.DispatcherServlet        : Completed 200 OK