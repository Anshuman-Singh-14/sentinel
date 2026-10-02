# Lab HTTPS target (compose profile "lab") for the header/TLS checker.
# A self-signed certificate is generated at build time: the checker should
# report it (HIGH) while finding the security headers well configured.
FROM alpine:3.22 AS cert
RUN apk add --no-cache openssl \
 && openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
      -keyout /lab.key -out /lab.crt -days 365 \
      -subj "/CN=lab-https" -addext "subjectAltName=DNS:lab-https"

FROM nginxinc/nginx-unprivileged:1.29-alpine
COPY --from=cert --chown=nginx:nginx /lab.crt /lab.key /etc/nginx/tls/
COPY default.conf /etc/nginx/conf.d/default.conf
EXPOSE 8080 8443
