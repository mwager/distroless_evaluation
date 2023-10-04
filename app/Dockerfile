# === Build:
# docker build -t cve_app .
# docker run -p 3000:8000 -d cve_app
# shell
# docker run -it --entrypoint /bin/sh cve_app
FROM node:20-bullseye AS base

# Copy source code and install NPM dependencies
WORKDIR /base
COPY main.js ./
COPY index.html ./
COPY package.json ./
RUN npm i

# install grype
RUN curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin

# of course this image uses a component reduction method ;-)
# bonus: chainguard images have a shell to execute the scans from within the app
FROM cgr.dev/chainguard/node:latest
COPY --from=base /base /base
COPY --from=base /usr/local/bin/grype /usr/local/bin/grype
WORKDIR /base

EXPOSE 8000
CMD ["main.js"]
