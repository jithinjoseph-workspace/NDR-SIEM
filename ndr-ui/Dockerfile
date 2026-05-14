FROM node:20 as build

WORKDIR /app

COPY package*.json ./

# Clean install (important)
RUN rm -rf node_modules package-lock.json
RUN npm install

COPY . .

# Fix permission issue
RUN chmod -R 755 node_modules/.bin

# Use direct node execution (no ng permission issue)
RUN node ./node_modules/@angular/cli/bin/ng build

FROM nginx:alpine

COPY --from=build /app/dist/ndr-ui/browser /usr/share/nginx/html


EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
