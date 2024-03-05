FROM almalinux:9

ARG REPO="https://yum.eu.choria.io/release/el/release.repo"

WORKDIR /
ENTRYPOINT ["/usr/sbin/aaasvc"]

RUN curl -s "${REPO}" > /etc/yum.repos.d/choria.repo && \
    yum -y install aaasvc nc procps-ng openssl && \
    yum -y clean all

RUN groupadd --gid 2048 choria && \
    useradd -c "Choria Orchestrator - choria.io" -m --uid 2048 --gid 2048 choria && \
    chown -R choria:choria /etc/aaasvc

ENV USER choria
USER choria
