# Quint, and the Java 21 runtime its Apalache and TLC backends need (formal/run.sh quint).
ARG NODE_IMAGE
ARG JRE_IMAGE
FROM ${NODE_IMAGE} AS node
FROM ${JRE_IMAGE}
ARG QUINT_VERSION
COPY --from=node /usr/local/bin/node /usr/local/bin/node
COPY --from=node /usr/local/lib/node_modules /usr/local/lib/node_modules
RUN ln -s /usr/local/lib/node_modules/npm/bin/npm-cli.js /usr/local/bin/npm && \
    npm install -g @informalsystems/quint@${QUINT_VERSION}
