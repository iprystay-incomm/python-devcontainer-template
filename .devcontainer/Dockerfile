FROM python:3.10

ARG USERNAME=nonroot

RUN apt update && \
    apt install -y sudo nvi && \
    echo "${USERNAME} ALL=(ALL)       NOPASSWD: ALL" | EDITOR='tee -a' visudo && \
    groupadd --gid 1000 ${USERNAME} && \
    useradd --uid 1000 --gid 1000 -m ${USERNAME}

COPY --chown=${USERNAME}:1000 requirements.txt /tmp/requirements.txt

## Make sure to reflect new user in PATH
ENV PATH="/home/${USERNAME}/.local/bin:${PATH}"
USER ${USERNAME}

RUN pip install --upgrade pip && \
    pip install -r /tmp/requirements.txt && \
    rm /tmp/requirements.txt
