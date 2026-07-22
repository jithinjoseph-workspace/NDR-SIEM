FROM node:20 AS build

WORKDIR /app

COPY package*.json ./

# Clean install (important)
RUN rm -rf node_modules package-lock.json
RUN npm install --legacy-peer-deps

COPY . .

# Fix permission issue
RUN chmod -R 755 node_modules/.bin

# Use direct node execution (no ng permission issue)
RUN node ./node_modules/@angular/cli/bin/ng build

FROM nginx:alpine

COPY --from=build /app/dist/ndr-ui/browser /usr/share/nginx/html

# Nginx config: serve Angular SPA + proxy /api → ndr-engine upstream
RUN printf 'events { worker_connections 1024; }\n\
http {\n\
  include       /etc/nginx/mime.types;\n\
  default_type  application/octet-stream;\n\
\n\
  upstream ndr_api {\n\
    server ndr-engine-1:8080;\n\
    server ndr-engine-2:8080;\n\
    server ndr-engine-3:8080;\n\
  }\n\
\n\
  server {\n\
    listen 80;\n\
\n\
    # Proxy all /api calls to the engine cluster\n\
    location /api/ {\n\
      proxy_pass         http://ndr_api/;\n\
      proxy_http_version 1.1;\n\
      proxy_set_header   Upgrade $http_upgrade;\n\
      proxy_set_header   Connection "upgrade";\n\
      proxy_set_header   Host $host;\n\
      proxy_read_timeout 300s;\n\
    }\n\
\n\
    # Serve Angular SPA — unknown routes fall back to index.html\n\
    location / {\n\
      root  /usr/share/nginx/html;\n\
      index index.html;\n\
      try_files $uri $uri/ /index.html;\n\
    }\n\
  }\n\
}\n' > /etc/nginx/nginx.conf

EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
